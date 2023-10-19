use std::{
    cell::RefCell,
    sync::{Arc, RwLock, Weak},
};

use crate::{
    common::{
        frim::FrimMap,
        roto::{FilterName, FilterOutput, RotoScripts, ThreadLocalVM},
        status_reporter::Chainable,
    },
    manager::{Component, WaitPoint},
    payload::{Payload, RouterId, SourceId}, http,
    // units::bmp_tcp_in::status_reporter::BmpTcpInStatusReporter,
};
use crate::{
    comms::{Gate, GateStatus, Terminated},
    units::Unit,
};
use crate::{
    tokio::TokioTaskMetrics,
    units::bmp_tcp_in::{
        metrics::BmpInMetrics,
        state_machine::{machine::BmpState, processing::MessageType},
        status_reporter::BmpInStatusReporter,
    },
};
use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use roto::types::{builtin::BuiltinTypeValue, collections::BytesRecord, typevalue::TypeValue};
use serde::Deserialize;
use toml::value::Datetime;

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::task::{Context, Poll};

use crate::common::unit::UnitActivity;

use bytes::BytesMut;
use futures::future::select;
use futures::stream::Empty;
use futures::{pin_mut, Future};

use routecore::bmp::message::Message;
use serve::buf::BufSource;
use serve::service::{
    CallResult,
    MsgLayout::{self, MsgContainsLen},
    MsgProvider, Service, ServiceError, Transaction,
};
use serve::sock::AsyncAccept;
use serve::stream::StreamServer;
use serve::ShortBuf;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

#[cfg(feature = "router-list")]
use super::{http::RouterListApi, types::RouterInfo};

use super::state_machine::metrics::BmpMetrics;
use super::util::format_source_id;

//-------- Constants ---------------------------------------------------------

pub const UNKNOWN_ROUTER_SYSNAME: &str = "unknown";

//-------- XXXX --------------------------------------------------------------

struct BmpBytes(Message<Bytes>);

/// Message length determination and deserialization for BMP message streams.
impl MsgProvider for BmpBytes {
    /// According to RFC 7854 "BGP Monitoring Protocol (BMP)" one must read 5
    /// bytes of an incoming message in order to know how many more bytes
    /// remain to be read.
    ///
    /// 4.1.  Common Header
    ///
    /// The following common header appears in all BMP messages.  The rest of
    /// the data in a BMP message is dependent on the Message Type field in
    /// the common header.
    ///
    ///    0                   1                   2                   3
    ///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///   +-+-+-+-+-+-+-+-+
    ///   |    Version    |
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///   |                        Message Length                         |
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///   |   Msg. Type   |
    ///   +---------------+
    ///
    /// From: https://datatracker.ietf.org/doc/html/rfc7854#section-4.1
    const MIN_HDR_BYTES: usize = 5;

    /// And thus we also know that the message length bytes are part of the
    /// actual BMP message that we want to have as the output of deserializing
    /// a complete BMP message byte sequence.
    const MSG_LAYOUT: MsgLayout = MsgContainsLen;

    /// Process incoming Bytes.
    type ReqOcts = Bytes;

    /// And deserialize them to BMP `Message` objects that refer to those
    /// read bytes.
    type Msg = Message<Self::ReqOcts>;

    fn len(hdr_buf: &[u8]) -> usize {
        let _version = hdr_buf[0];
        // SAFETY: we should only be invoked once MSG_HDR_BYTES worth of bytes
        // have already been read and so should be safe to index into at least
        // that many bytes of the given header buffer.
        u32::from_be_bytes(hdr_buf[1..5].try_into().unwrap()) as usize
    }

    fn from_octets(octets: Self::ReqOcts) -> Result<Self::Msg, ShortBuf> {
        // TODO: Do something with the error message?
        Message::from_octets(octets).map_err(|_err| ShortBuf)
    }
}

pub type SrvOut = Result<CallResult<BytesMut>, ServiceError<()>>;

#[cfg(feature = "router-list")]
#[derive(Clone, Debug)]
pub struct ConnSummary {
    pub connected_at: Arc<DateTime<Utc>>,
    pub last_msg_at: Arc<RwLock<DateTime<Utc>>>,
    pub bmp_state: Weak<RwLock<Option<BmpState>>>,
}

#[derive(Default)]
struct BmpStreamState {
    source_id: SourceId,

    gate: Arc<Gate>, // TODO: this should be an Arc<ArcSwap<..>> so it can be reconfigured

    status_reporter: Arc<BmpInStatusReporter>,

    bmp_state: Arc<RwLock<Option<BmpState>>>,

    router_id_template: Arc<ArcSwap<String>>,

    roto_scripts: RotoScripts,

    filter_name: Arc<ArcSwap<FilterName>>,

    #[cfg(feature = "router-list")]
    conn_summaries: Arc<FrimMap<SocketAddr, ConnSummary>>,
}

#[derive(Clone, Debug)]
struct BmpTcpStreamServiceFactory;

impl BmpTcpStreamServiceFactory {
    thread_local!(
        static VM: ThreadLocalVM = RefCell::new(None);
    );

    fn build(
        gate: Gate,
        bmp_metrics: Arc<BmpMetrics>,
        status_reporter: Arc<BmpInStatusReporter>,
        router_id_template: Arc<ArcSwap<String>>,
        roto_scripts: RotoScripts,
        filter_name: Arc<ArcSwap<FilterName>>,
        #[cfg(feature = "router-list")] conn_summaries: Arc<FrimMap<SocketAddr, ConnSummary>>,
    ) -> impl Service<SocketAddr, BmpBytes, BmpStreamState> {
        // The inner clones are a problem, they'll happen on EVERY message.
        // This is due to the lack of strict ordering of processing of messages
        // for a single TCP stream, even with the introduction of
        // Transaction::OrderedXxx() which does guarantee ordering but the
        // compiler can't tell that so can't let us use a single cloned gate
        // per stream.
        let connect_fn = move |addr| {
            Self::connect(
                addr,
                gate.clone(),
                bmp_metrics.clone(),
                status_reporter.clone(),
                router_id_template.clone(),
                roto_scripts.clone(),
                filter_name.clone(),
                #[cfg(feature = "router-list")]
                conn_summaries.clone(),
            )
        };

        (connect_fn, Self::call, Self::disconnect)
    }

    fn connect(
        addr: SocketAddr,
        gate: Gate,
        bmp_metrics: Arc<BmpMetrics>,
        status_reporter: Arc<BmpInStatusReporter>,
        router_id_template: Arc<ArcSwap<String>>,
        roto_scripts: RotoScripts,
        filter_name: Arc<ArcSwap<FilterName>>,
        #[cfg(feature = "router-list")] conn_summaries: Arc<FrimMap<SocketAddr, ConnSummary>>,
    ) -> Result<Option<BmpStreamState>, ()> {
        // TODO: add a router_info entry for this router

        // TODO: setup router specific API endpoint

        let source_id = SourceId::from(addr);

        let router_id = Arc::new(format_source_id(
            &router_id_template.load(),
            UNKNOWN_ROUTER_SYSNAME,
            &source_id,
        ));

        // Choose a name to be reported in application logs.
        let child_name = format!("router[{}]", source_id);

        // Create a status reporter whose name in output will be a combination
        // of ours as parent and the newly chosen child name, enabling logged
        // messages relating to this newly connected router to be
        // distinguished from logged messages relating to other connected
        // routers.
        let status_reporter = Arc::new(status_reporter.add_child(child_name));

        let bmp_state = BmpState::new(
            source_id.clone(),
            router_id,
            status_reporter.clone(),
            bmp_metrics,
        );

        let bmp_state = Arc::new(RwLock::new(Some(bmp_state)));

        let custom_state = BmpStreamState {
            status_reporter,
            source_id,
            gate: gate.into(),
            bmp_state,
            router_id_template,
            roto_scripts,
            filter_name,
            #[cfg(feature = "router-list")]
            conn_summaries,
        };

        Ok(Some(custom_state))
    }

    #[allow(clippy::type_complexity)]
    fn call<SrvErr>(
        addr: SocketAddr,
        msg: Message<Bytes>,
        custom_state: Option<BmpStreamState>,
    ) -> Result<
        (
            Transaction<impl Future<Output = SrvOut>, Empty<SrvOut>>,
            Option<BmpStreamState>,
        ),
        ServiceError<SrvErr>,
    > {
        let custom_state = custom_state.unwrap();

        {
            let bmp_state_read_lock = custom_state.bmp_state.read().unwrap(); // SAFETY: should never be poisoned
            let bmp_state = bmp_state_read_lock.as_ref().unwrap(); // SAFETY: should already have been set to Some by connect()

            custom_state
                .status_reporter
                .bmp_message_received(bmp_state.router_id());
        }

        #[cfg(feature = "router-list")]
        if let Some(conn_summary) = custom_state.conn_summaries.get(&addr) {
            let mut guard = conn_summary.last_msg_at.write().unwrap();
            *guard = Utc::now();
        } else {
            let now = Utc::now();
            let conn_summary = ConnSummary {
                connected_at: Arc::new(now.clone()),
                last_msg_at: Arc::new(RwLock::new(now)),
                bmp_state: Arc::downgrade(&custom_state.bmp_state),
            };
            custom_state.conn_summaries.insert(addr, conn_summary);
        }

        if let Ok(ControlFlow::Continue(FilterOutput { south, east })) = Self::VM.with(|vm| {
            let value =
                TypeValue::Builtin(BuiltinTypeValue::BmpMessage(Arc::new(BytesRecord(msg))));
            custom_state
                .roto_scripts
                .exec(vm, &custom_state.filter_name.load(), value)
        }) {
            let gate = custom_state.gate.clone();
            let mut south_update = None;
            let mut east_update = None;

            if !south.is_empty() {
                south_update = Some(
                    Payload::from_output_stream_queue(custom_state.source_id.clone(), south).into(),
                );
            }

            if let TypeValue::Builtin(BuiltinTypeValue::BmpMessage(msg)) = east {
                let msg = Arc::into_inner(msg).unwrap(); // This should succeed
                let msg = msg.0;

                let mut bmp_state_lock = custom_state.bmp_state.write().unwrap(); // SAFETY: should never be poisoned
                let bmp_state = bmp_state_lock.take().unwrap();

                custom_state
                    .status_reporter
                    .bmp_message_processed(bmp_state.router_id());

                let mut res = bmp_state.process_msg(msg);

                match res.processing_result {
                    MessageType::InvalidMessage {
                        err,
                        known_peer,
                        msg_bytes,
                    } => {
                        custom_state
                            .status_reporter
                            .invalid_bmp_message_received(res.next_state.router_id());
                        if let Some(reporter) = res.next_state.status_reporter() {
                            reporter.bgp_update_parse_hard_fail(
                                res.next_state.router_id(),
                                known_peer,
                                err,
                                msg_bytes,
                            );
                        }
                    }

                    MessageType::StateTransition => {
                        // If we have transitioned to the Dumping state that means we
                        // just processed an Initiation message and MUST have captured
                        // a sysName Information TLV string. Use the captured value to
                        // make the router ID more meaningful, instead of the
                        // UNKNOWN_ROUTER_SYSNAME sysName value we used until now.
                        Self::check_update_router_id(addr, &mut res.next_state, &custom_state);
                    }

                    MessageType::RoutingUpdate { update } => {
                        // Pass the routing update on to downstream units and/or targets.
                        // This is where we send an update down the pipeline.
                        east_update = Some(update);
                    }

                    MessageType::Other => {
                        // A BMP initiation message received after the initiation
                        // phase will result in this type of message.
                        Self::check_update_router_id(addr, &mut res.next_state, &custom_state);
                    }

                    MessageType::Aborted => {
                        // Something went fatally wrong, the issue should already have
                        // been logged so there's nothing more we can do here.
                    }
                }

                *bmp_state_lock = Some(res.next_state);
            }

            let txn = Transaction::OrderedSingle(async move {
                if let Some(update) = south_update {
                    gate.update_data(update).await;
                }
                if let Some(update) = east_update {
                    gate.update_data(update).await;
                }

                // This strange looking return error is a hack to say that there is no
                // response message... TO DO: make a better API for this... sigh.
                Err(ServiceError::ServiceSpecificError(()))
            });

            Ok((txn, Some(custom_state)))
        } else {
            // custom_state.status_reporter.bmp_message_filtered()
            todo!()
        }
    }

    fn disconnect(addr: SocketAddr, custom_state: Option<BmpStreamState>) {
        // custom_state.status_reporter.router_connection_lost(addr)
    }

    fn check_update_router_id(
        addr: SocketAddr,
        next_state: &mut BmpState,
        custom_state: &BmpStreamState,
    ) {
        let new_sys_name = match next_state {
            BmpState::Dumping(v) => &v.details.sys_name,
            BmpState::Updating(v) => &v.details.sys_name,
            _ => {
                // Other states don't carry the sys name
                return;
            }
        };

        let new_router_id = Arc::new(format_source_id(
            &custom_state.router_id_template.load(),
            new_sys_name,
            &custom_state.source_id,
        ));

        let old_router_id = next_state.router_id();
        if new_router_id != old_router_id {
            // Ensure that on first use the metrics for this
            // new router ID are correctly initialised.
            custom_state
                .status_reporter
                .router_id_changed(old_router_id, new_router_id.clone());

            match next_state {
                BmpState::Dumping(v) => v.router_id = new_router_id.clone(),
                BmpState::Updating(v) => v.router_id = new_router_id.clone(),
                _ => unreachable!(),
            }

            #[cfg(feature = "router-list")]
            if let Some(conn_summary) = custom_state.conn_summaries.get(&addr) {
                let mut new_conn_summary = conn_summary.clone();
                let (sys_name, sys_desc) = match next_state {
                    BmpState::Dumping(v) => (&v.details.sys_name, &v.details.sys_desc),
                    BmpState::Updating(v) => (&v.details.sys_name, &v.details.sys_desc),
                    _ => unreachable!(),
                };
            }
        }
    }
}

//--- TCP listener traits ----------------------------------------------------
//
// These traits enable us to swap out the real TCP listener for a mock when
// testing.

#[async_trait::async_trait]
trait TcpListenerFactory<T> {
    async fn bind(&self, addr: &str) -> std::io::Result<T>;
}

#[async_trait::async_trait]
trait TcpListener {
    async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)>;
}

struct StandardTcpListenerFactory;

#[async_trait::async_trait]
impl TcpListenerFactory<StandardTcpListener> for StandardTcpListenerFactory {
    async fn bind(&self, addr: &str) -> std::io::Result<StandardTcpListener> {
        let listener = ::tokio::net::TcpListener::bind(addr).await?;
        Ok(StandardTcpListener(listener))
    }
}

struct StandardTcpListener(::tokio::net::TcpListener);

#[async_trait::async_trait]
impl TcpListener for StandardTcpListener {
    async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        self.0.accept().await
    }
}

impl AsyncAccept for StandardTcpListener {
    type Addr = SocketAddr;
    type Error = std::io::Error;
    type StreamType = TcpStream;
    type Stream = futures::future::Ready<Result<Self::StreamType, std::io::Error>>;

    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, Self::Addr), std::io::Error>> {
        tokio::net::TcpListener::poll_accept(&self.0, cx)
            .map(|res| res.map(|(stream, addr)| (futures::future::ready(Ok(stream)), addr)))
    }
}

//-------- BmpIn -------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct BmpTcpIn {
    /// A colon separated IP address and port number to listen on for incoming
    /// BMP over TCP connections from routers.
    ///
    /// On change: existing connections to routers will be unaffected, new
    ///            connections will only be accepted at the changed URI.
    pub listen: Arc<String>,

    /// The relative path at which we should listen for HTTP query API requests
    #[cfg(feature = "router-list")]
    #[serde(default = "BmpTcpIn::default_http_api_path")]
    http_api_path: Arc<String>,

    #[serde(default = "BmpTcpIn::default_router_id_template")]
    pub router_id_template: String,

    #[serde(default)]
    pub filter_name: FilterName,
}

impl BmpTcpIn {
    pub async fn run(
        self,
        mut component: Component,
        gate: Gate,
        mut waitpoint: WaitPoint,
    ) -> Result<(), Terminated> {
        let unit_name = component.name().clone();

        // Setup our metrics
        let bmp_in_metrics = Arc::new(BmpInMetrics::new(&gate));
        component.register_metrics(bmp_in_metrics.clone());

        // Setup metrics to be updated by the BMP state machines that we use
        // to make sense of the BMP data per router that supplies it.
        let bmp_metrics = Arc::new(BmpMetrics::new());
        component.register_metrics(bmp_metrics.clone());

        let state_machine_metrics = Arc::new(TokioTaskMetrics::new());
        component.register_metrics(state_machine_metrics.clone());

        // Setup our status reporting
        let status_reporter =
            Arc::new(BmpInStatusReporter::new(&unit_name, bmp_in_metrics.clone()));

        // Setup REST API endpoint
        #[cfg(feature = "router-list")]
        let (_api_processor, conn_summaries) = {
            let conn_summaries = Arc::new(FrimMap::default());

            let processor = Arc::new(RouterListApi::new(
                component.http_resources().clone(),
                self.http_api_path.clone(),
                bmp_in_metrics.clone(),
                bmp_metrics.clone(),
                conn_summaries.clone(),
            ));

            component.register_http_resource(processor.clone(), &self.http_api_path);

            (processor, conn_summaries)
        };

        let roto_scripts = component.roto_scripts().clone();

        // Wait for other components to be, and signal to other components
        // that we are, ready to start. All units and targets start together,
        // otherwise data passed from one component to another may be lost if
        // the receiving component is not yet ready to accept it.
        gate.process_until(waitpoint.ready()).await?;

        // Signal again once we are out of the process_until() so that anyone
        // waiting to send important gate status updates won't send them while
        // we are in process_until() which will just eat them without handling
        // them.
        waitpoint.running().await;

        let router_id_template = Arc::new(ArcSwap::from_pointee(self.router_id_template.clone()));

        let filter_name = Arc::new(ArcSwap::from_pointee(self.filter_name.clone()));

        let service = BmpTcpStreamServiceFactory::build(
            gate.clone(),
            bmp_metrics.clone(),
            status_reporter.clone(),
            router_id_template.clone(),
            roto_scripts.clone(),
            filter_name.clone(),
            #[cfg(feature = "router-list")]
            conn_summaries,
        );

        BmpInRunner::new(
            self.listen.clone(),
            self.http_api_path.clone(),
            gate,
            bmp_metrics,
            bmp_in_metrics,
            state_machine_metrics,
            status_reporter,
            roto_scripts,
            router_id_template,
            filter_name,
        )
        .run(Arc::new(StandardTcpListenerFactory), service.into())
        .await
    }

    #[cfg(feature = "router-list")]
    fn default_http_api_path() -> Arc<String> {
        Arc::new("/routers/".to_string())
    }

    pub fn default_router_id_template() -> String {
        "{sys_name}".to_string()
    }
}

//-------- BytesBufSource ----------------------------------------------------

struct BytesBufSource;

impl BufSource for BytesBufSource {
    type Output = BytesMut;

    fn create_buf(&self) -> Self::Output {
        BytesMut::new()
    }

    fn create_sized(&self, size: usize) -> Self::Output {
        let mut buf = BytesMut::with_capacity(size);
        buf.resize(size, 0);
        buf
    }
}

//-------- BmpInRunner -------------------------------------------------------

struct BmpInRunner {
    listen: Arc<String>,
    http_api_path: Arc<String>,
    gate: Gate,
    _bmp_metrics: Arc<BmpMetrics>,
    _bmp_in_metrics: Arc<BmpInMetrics>,
    _state_machine_metrics: Arc<TokioTaskMetrics>,
    status_reporter: Arc<BmpInStatusReporter>,
    roto_scripts: RotoScripts,
    router_id_template: Arc<ArcSwap<String>>,
    filter_name: Arc<ArcSwap<FilterName>>,
}

impl BmpInRunner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        listen: Arc<String>,
        http_api_path: Arc<String>,
        gate: Gate,
        bmp_metrics: Arc<BmpMetrics>,
        bmp_in_metrics: Arc<BmpInMetrics>,
        state_machine_metrics: Arc<TokioTaskMetrics>,
        status_reporter: Arc<BmpInStatusReporter>,
        roto_scripts: RotoScripts,
        router_id_template: Arc<ArcSwap<String>>,
        filter_name: Arc<ArcSwap<FilterName>>,

    ) -> Self {
        Self {
            listen: listen,
            http_api_path: http_api_path,
            gate,
            _bmp_metrics: bmp_metrics,
            _bmp_in_metrics: bmp_in_metrics,
            _state_machine_metrics: state_machine_metrics,
            status_reporter,
            roto_scripts,
            router_id_template,
            filter_name,
        }
    }

    #[cfg(test)]
    pub(crate) fn mock() -> (Self, crate::comms::GateAgent) {
        let (gate, gate_agent) = Gate::new(0);

        let runner = Self {
            listen: Default::default(),
            http_api_path: BmpTcpIn::default_http_api_path().into(),
            gate,
            _bmp_metrics: Default::default(),
            _bmp_in_metrics: Default::default(),
            _state_machine_metrics: Default::default(),
            status_reporter: Default::default(),
            roto_scripts: Default::default(),
            router_id_template: Default::default(),
            filter_name: Default::default(),
        };

        (runner, gate_agent)
    }

    async fn run<ListenerFactory, Listener, Svc, MsgTyp, CustomState>(
        mut self,
        listener_factory: Arc<ListenerFactory>,
        service_factory: Arc<Svc>,
    ) -> Result<(), crate::comms::Terminated>
    where
        ListenerFactory: TcpListenerFactory<Listener>,
        Listener: TcpListener + Send + AsyncAccept + 'static,
        Svc: Service<<Listener as AsyncAccept>::Addr, MsgTyp, CustomState> + Send + Sync + 'static,
        MsgTyp: MsgProvider + Send + Sync + 'static,
        <MsgTyp as MsgProvider>::ReqOcts: std::convert::From<BytesMut> + Send + Sync,
        <MsgTyp as MsgProvider>::Msg: Send,
        CustomState: Send + Sync + 'static,
    {
        // Loop until terminated, accepting TCP connections from routers and
        // spawning tasks to handle them.
        // let status_reporter = self.status_reporter.clone();
        let buf_source = Arc::new(BytesBufSource);

        loop {
            let listen_addr = self.listen.clone();

            let bind_with_backoff = || async {
                let mut wait = 1;
                loop {
                    match listener_factory.bind(&listen_addr).await {
                        Err(_err) => {
                            // let err = format!("{err}: Will retry in {wait} seconds.");
                            // status_reporter.bind_error(&listen_addr, &err);
                            sleep(Duration::from_secs(wait)).await;
                            wait *= 2;
                        }
                        res => break res,
                    }
                }
            };

            let listener = match self.process_until(bind_with_backoff()).await {
                ControlFlow::Continue(Ok(res)) => res,
                ControlFlow::Continue(Err(_err)) => continue,
                ControlFlow::Break(Terminated) => return Err(Terminated),
            };

            // status_reporter.listener_listening(&listen_addr);

            let srv = StreamServer::new(listener, buf_source.clone(), service_factory.clone());
            let srv = Arc::new(srv);

            match self.process_until(srv.clone().run()).await {
                ControlFlow::Continue(Ok(_v)) => { /* TODO: The TCP server shutdown... what now? */
                }
                ControlFlow::Continue(Err(_err)) => {
                    // Stop listening on the current listen port.
                    if let Err(err) = srv.shutdown() {
                        eprintln!("Error while shutting down TCP server: {err}");
                    }
                    eprintln!("Rebinding...");
                }
                ControlFlow::Break(Terminated) => {
                    if let Err(err) = srv.shutdown() {
                        eprintln!("Error while shutting down TCP server: {err}");
                    }
                    return Err(Terminated);
                }
            }
        }
    }

    async fn process_until<T, U>(
        &mut self,
        until_fut: T,
    ) -> ControlFlow<Terminated, std::io::Result<U>>
    where
        T: Future<Output = std::io::Result<U>>,
    {
        let mut until_fut = Box::pin(until_fut);

        loop {
            let process_fut = self.gate.process();
            pin_mut!(process_fut);

            let res = select(process_fut, until_fut).await;

            match (&self.status_reporter, res).into() {
                UnitActivity::GateStatusChanged(status, next_fut) => {
                    match status {
                        GateStatus::Reconfiguring {
                            new_config: Unit::BmpTcpIn(BmpTcpIn {
                                listen: new_listen,
                                http_api_path: _http_api_path,
                                router_id_template: new_router_id_template,
                                filter_name: new_filter_name,
                            }),
                        } => {
                            // Runtime reconfiguration of this unit has
                            // been requested. New connections will be
                            // handled using the new configuration,
                            // existing connections handled by
                            // router_handler() tasks will receive their
                            // own copy of this Reconfiguring status
                            // update and can react to it accordingly.
                            let rebind = self.listen != new_listen;

                            self.listen = new_listen;
                            self.filter_name.store(new_filter_name.into());
                            self.router_id_template.store(new_router_id_template.into());

                            if rebind {
                                // Trigger re-binding to the new listen port.
                                let err = std::io::ErrorKind::Other;
                                return ControlFlow::Continue(Err(err.into()));
                            }
                        }

                        GateStatus::ReportLinks { report } => {
                            report.declare_source();
                            // report.set_graph_status(self.metrics.clone());
                        }

                        _ => { /* Nothing to do */ }
                    }

                    until_fut = next_fut;
                }

                UnitActivity::InputError(err) => {
                    // self.status_reporter.listener_io_error(&err);
                    return ControlFlow::Continue(Err(err));
                }

                UnitActivity::InputReceived(v) => {
                    return ControlFlow::Continue(Ok(v));
                }

                UnitActivity::Terminated => {
                    // self.status_reporter.terminated();
                    return ControlFlow::Break(Terminated);
                }
            }
        }
    }
}

impl std::fmt::Debug for BmpInRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BmpInRunner").finish()
    }
}

// --- Tests ----------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use roto::types::{collections::BytesRecord, lazyrecord_types::BmpMessage};

    use crate::{
        bgp::encode::{
            mk_initiation_msg, mk_invalid_initiation_message_that_lacks_information_tlvs,
            mk_peer_down_notification_msg, mk_per_peer_header,
        },
        tests::util::internal::get_testable_metrics_snapshot,
    };

    use super::*;

    const SYS_NAME: &str = "some sys name";
    const SYS_DESCR: &str = "some sys descr";
    const OTHER_SYS_NAME: &str = "other sys name";

    #[test]
    fn sources_are_required() {
        // suppress the panic backtrace as we expect the panic
        std::panic::set_hook(Box::new(|_| {}));

        // parse and panic due to missing 'sources' field
        assert!(mk_config_from_toml("").is_err());
    }

    #[test]
    fn sources_must_be_non_empty() {
        assert!(mk_config_from_toml("sources = []").is_err());
    }

    #[test]
    fn okay_with_one_source() {
        let toml = r#"
        sources = ["some source"]
        "#;

        mk_config_from_toml(toml).unwrap();
    }

    // Note: The tests below assume that the default router id template
    // includes the BMP sysName.

    #[tokio::test(flavor = "multi_thread")]
    #[should_panic]
    async fn counters_for_expected_sys_name_should_not_exist() {
        let (runner, _) = BmpInRunner::mock();
        let initiation_msg = mk_update(mk_initiation_msg(SYS_NAME, SYS_DESCR));

        runner.process_update(initiation_msg).await;

        let metrics = get_testable_metrics_snapshot(&runner.status_reporter.metrics().unwrap());
        assert_eq!(
            metrics.with_label::<usize>("bmp_in_num_invalid_bmp_messages", ("router", SYS_NAME)),
            0,
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[should_panic]
    async fn counters_for_other_sys_name_should_not_exist() {
        let (runner, _) = BmpInRunner::mock();
        let initiation_msg = mk_update(mk_initiation_msg(SYS_NAME, SYS_DESCR));

        runner.process_update(initiation_msg).await;

        let metrics = get_testable_metrics_snapshot(&runner.status_reporter.metrics().unwrap());
        assert_eq!(
            metrics.with_label::<usize>(
                "bmp_in_num_invalid_bmp_messages",
                ("router", OTHER_SYS_NAME)
            ),
            0,
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn num_invalid_bmp_messages_counter_should_increase() {
        let (runner, _) = BmpInRunner::mock();

        // A BMP Initiation message that lacks required fields
        let bad_initiation_msg =
            mk_update(mk_invalid_initiation_message_that_lacks_information_tlvs());

        // A BMP Peer Down Notification message without a corresponding Peer
        // Up Notification message.
        let pph = mk_per_peer_header("10.0.0.1", 12345);
        let bad_peer_down_msg = mk_update(mk_peer_down_notification_msg(&pph));

        runner.process_update(bad_initiation_msg).await;
        runner.process_update(bad_peer_down_msg).await;

        let metrics = get_testable_metrics_snapshot(&runner.status_reporter.metrics().unwrap());
        assert_eq!(
            metrics.with_label::<usize>(
                "bmp_in_num_invalid_bmp_messages",
                ("router", UNKNOWN_ROUTER_SYSNAME)
            ),
            2,
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_counters_should_be_started_if_the_router_id_changes() {
        let (runner, _) = BmpInRunner::mock();
        let initiation_msg = mk_update(mk_initiation_msg(SYS_NAME, SYS_DESCR));
        let pph = mk_per_peer_header("10.0.0.1", 12345);
        let bad_peer_down_msg = mk_update(mk_peer_down_notification_msg(&pph));
        let reinitiation_msg = mk_update(mk_initiation_msg(OTHER_SYS_NAME, SYS_DESCR));
        let another_bad_peer_down_msg = mk_update(mk_peer_down_notification_msg(&pph));

        runner.process_update(initiation_msg).await;
        runner.process_update(bad_peer_down_msg).await;
        runner.process_update(reinitiation_msg).await;
        runner.process_update(another_bad_peer_down_msg).await;

        let metrics = get_testable_metrics_snapshot(&runner.status_reporter.metrics().unwrap());
        assert_eq!(
            metrics.with_label::<usize>("bmp_in_num_invalid_bmp_messages", ("router", SYS_NAME)),
            1,
        );
        assert_eq!(
            metrics.with_label::<usize>(
                "bmp_in_num_invalid_bmp_messages",
                ("router", OTHER_SYS_NAME)
            ),
            1,
        );
    }

    // --- Test helpers ------------------------------------------------------

    fn mk_config_from_toml(toml: &str) -> Result<BmpTcpIn, toml::de::Error> {
        toml::from_str::<BmpTcpIn>(toml)
    }

    fn mk_update(msg_buf: Bytes) -> Update {
        let source_id = SourceId::SocketAddr("127.0.0.1:8080".parse().unwrap());
        let bmp_msg = Arc::new(BytesRecord(BmpMessage::from_octets(msg_buf).unwrap()));
        let value = TypeValue::Builtin(BuiltinTypeValue::BmpMessage(bmp_msg));
        Update::Single(Payload::new(source_id, value))
    }
}
