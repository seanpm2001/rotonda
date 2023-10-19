use std::{
    net::SocketAddr,
    ops::Deref,
    sync::{atomic::Ordering, Arc},
};

use async_trait::async_trait;
use hyper::{Body, Method, Request, Response};

use crate::{
    common::frim::FrimMap,
    http::{self, extract_params, get_param, MatchedParam, PercentDecodedPath, ProcessRequest},
    payload::SourceId,
    units::bmp_tcp_in::{
        http::{router_info::Focus, RouterInfoApi},
        metrics::BmpInMetrics,
        state_machine::{machine::BmpState, metrics::BmpMetrics},
        unit::ConnSummary,
        util::calc_u8_pc,
    },
};

pub struct RouterListApi {
    http_resources: http::Resources,
    http_api_path: Arc<String>,
    pub bmp_in_metrics: Arc<BmpInMetrics>,
    pub bmp_metrics: Arc<BmpMetrics>,
    pub conn_summaries: Arc<FrimMap<SocketAddr, ConnSummary>>,
}

#[async_trait]
impl ProcessRequest for RouterListApi {
    async fn process_request(&self, request: &Request<Body>) -> Option<Response<Body>> {
        let req_path = request.uri().decoded_path();
        if request.method() == Method::GET && req_path == *self.http_api_path {
            let http_api_path =
                html_escape::encode_double_quoted_attribute(self.http_api_path.deref());

            // If sorting has been requested, extract the value to sort on and the key, store them as a vec of
            // tuples, and sort the vec, then lookup each router_info key in the order of the keys in the sorted
            // vec.
            let params = extract_params(request);
            let sort_by = get_param(&params, "sort_by");
            let sort_order = get_param(&params, "sort_order");

            let response = match self.sort_routers(sort_by, sort_order).await {
                Ok(keys) => self.build_response(keys, http_api_path).await,

                Err(err) => Response::builder()
                    .status(hyper::StatusCode::BAD_REQUEST)
                    .header("Content-Type", "text/plain")
                    .body(err.into())
                    .unwrap(),
            };

            return Some(response);
        } else if request.method() == Method::GET
            && req_path.starts_with(self.http_api_path.deref())
        {
            let (base_path, router) = req_path.split_at(self.http_api_path.len());

            let (router, focus) = if let Some((router, peer)) = router.split_once("/prefixes/") {
                (router, Focus::Prefixes(peer.to_string()))
            } else if let Some((router, peer)) = router.split_once("/flags/") {
                (router, Focus::Flags(peer.to_string()))
            } else {
                (router, Focus::None)
            };

            let router = router.to_string();

            let addr_res = router
                .parse::<SocketAddr>()
                .map_err(|err| err.to_string())
                .and_then(|addr| {
                    self.conn_summaries
                        .get(&addr)
                        .map(|conn_summary| (addr, conn_summary))
                        .ok_or(format!("'{addr}' is not a known BMP router address"))
                })
                .or_else(|_err| {
                    // It's not a socket address, so is it instead a known BMP router ID or sysName?
                    self.conn_summaries
                        .guard()
                        .iter()
                        .find(|(_, conn_summary)| {
                            if let Some(bmp_state_locked) = conn_summary.bmp_state.upgrade() {
                                let bmp_state = bmp_state_locked.read().unwrap();
                                if let Some(bmp_state) = bmp_state.deref() {
                                    #[rustfmt::skip]
                                    let (router_id, sys_name) = match bmp_state {
                                        BmpState::Initiating(v) => (Some(v.router_id.as_str()), v.details.sys_name.clone()),
                                        BmpState::Dumping(v) => (Some(v.router_id.as_str()), Some(v.details.sys_name.clone())),
                                        BmpState::Updating(v) => (Some(v.router_id.as_str()), Some(v.details.sys_name.clone())),
                                        BmpState::Terminated(_) => (None, None),
                                        BmpState::Aborted(_, router_id) => (Some(router_id.as_str()), None),
                                    };

                                    if let (Some(router_id), Some(sys_name)) = (router_id, sys_name) {
                                        return router == router_id || router == sys_name;
                                    }
                                }
                            }
                            false
                        })
                        .cloned()
                        .ok_or(format!(
                            "'{router}' is not a known BMP router address, router ID or sysName"
                        ))
                });

            let Ok((addr, conn_summary)) = addr_res else {
                return Some(
                    Response::builder()
                        .status(hyper::StatusCode::BAD_REQUEST)
                        .header("Content-Type", "text/plain")
                        .body(addr_res.unwrap_err().into())
                        .unwrap(),
                );
            };

           let source_id = SourceId::from(addr);
           if let Some(bmp_state_locked) = conn_summary.bmp_state.upgrade() {
                let bmp_state = bmp_state_locked.read().unwrap();

                let (router_id, sys_name, sys_desc, sys_extra, peer_states) = match bmp_state.deref() {
                    Some(BmpState::Dumping(v)) => (
                        v.router_id.clone(),
                        v.details.sys_name.clone(),
                        v.details.sys_desc.clone(),
                        v.details.sys_extra.clone(),
                        Some(&v.details.peer_states),
                    ),
                    Some(BmpState::Updating(v)) => (
                        v.router_id.clone(),
                        v.details.sys_name.clone(),
                        v.details.sys_desc.clone(),
                        v.details.sys_extra.clone(),
                        Some(&v.details.peer_states),
                    ),
                    _ => {
                        // no TLVs available
                        (Arc::new("".into()), String::new(), String::new(), vec![], None)
                    }
                };

                return Some(RouterInfoApi::build_response(
                    self.http_resources.clone(),
                    format!("{}{}", base_path, router).into(),
                    source_id,
                    router_id,
                    &sys_name,
                    &sys_desc,
                    &sys_extra,
                    peer_states,
                    focus,
                    &self.bmp_in_metrics,
                    &self.bmp_metrics,
                    &conn_summary.connected_at,
                    &conn_summary.last_msg_at,
                ));
            }
        }

        None
    }
}

impl RouterListApi {
    pub fn new(
        http_resources: http::Resources,
        http_api_path: Arc<String>,
        router_metrics: Arc<BmpInMetrics>,
        bmp_metrics: Arc<BmpMetrics>,
        conn_summaries: Arc<FrimMap<SocketAddr, ConnSummary>>,
    ) -> Self {
        Self {
            http_resources,
            http_api_path,
            bmp_in_metrics: router_metrics,
            bmp_metrics,
            conn_summaries,
        }
    }

    async fn sort_routers<'a>(
        &self,
        sort_by: Option<MatchedParam<'a>>,
        sort_order: Option<MatchedParam<'a>>,
    ) -> Result<Vec<SocketAddr>, String> {
        let sort_by = sort_by.as_ref().map(MatchedParam::value);

        let mut keys: Vec<SocketAddr> = match sort_by {
            None | Some("addr") => self
                .conn_summaries
                .guard()
                .iter()
                .map(|(k, _v)| *k)
                .collect(),

            Some("sys_name") | Some("sys_desc") => {
                let mut sort_tmp: Vec<(String, SocketAddr)> = Vec::new();

                for (addr, summary) in self.conn_summaries.guard().iter() {
                    if let Some(bmp_state_locked) = summary.bmp_state.upgrade() {
                        if let Some(bmp_state) = bmp_state_locked.read().unwrap().deref() {
                            let (sys_name, sys_desc) = match bmp_state {
                                BmpState::Dumping(v) => {
                                    (Some(v.details.sys_name.clone()), Some(v.details.sys_desc.clone()))
                                }
                                BmpState::Updating(v) => {
                                    (Some(v.details.sys_name.clone()), Some(v.details.sys_desc.clone()))
                                }
                                _ => {
                                    // no TLVs available
                                    (None, None)
                                }
                            };
    
                            let resolved_v = match sort_by {
                                Some("sys_name") => sys_name,
                                Some("sys_desc") => sys_desc,
                                _ => None,
                            }
                            .or_else(|| Some("-".to_string()))
                            .unwrap();
        
                            sort_tmp.push((resolved_v, *addr));
                        }
                    }
                }

                sort_tmp.sort_unstable_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
                sort_tmp.iter().map(|(_k, v)| *v).collect()
            }

            Some("state")
            | Some("peers_up")
            | Some("peers_up_eor_capable")
            | Some("peers_up_dumping")
            | Some("peers_up_eor_capable_pc")
            | Some("peers_up_dumping_pc")
            | Some("invalid_messages")
            | Some("soft_parse_errors")
            | Some("hard_parse_errors") => {
                let mut sort_tmp: Vec<(usize, SocketAddr)> = Vec::new();

                for (addr, conn_summary) in self.conn_summaries.guard().iter() {
                    if let Some(bmp_state_locked) = conn_summary.bmp_state.upgrade() {
                        let bmp_state = bmp_state_locked.read().unwrap();

                        let details = match bmp_state.deref() {
                            Some(BmpState::Dumping(v)) => Some(v.router_id.clone()),
                            Some(BmpState::Updating(v)) => Some(v.router_id.clone()),
                            _ => {
                                // no TLVs available
                                None
                            }
                        };

                        let resolved_v = if let Some(router_id) = details {
                            let metrics = self.bmp_metrics.router_metrics(router_id.clone());

                            match sort_by {
                                Some("state") => metrics.bmp_state_machine_state.load(Ordering::SeqCst) as usize,

                                Some("peers_up") => metrics.num_peers_up.load(Ordering::SeqCst),

                                Some("peers_up_eor_capable") => metrics.num_peers_up_eor_capable.load(Ordering::SeqCst),

                                Some("peers_up_dumping") => metrics.num_peers_up_dumping.load(Ordering::SeqCst),

                                Some("peers_up_eor_capable_pc") => {
                                    let total = metrics.num_peers_up.load(Ordering::SeqCst);
                                    let v = metrics.num_peers_up_eor_capable.load(Ordering::SeqCst);
                                    calc_u8_pc(total, v).into()
                                }
                                Some("peers_up_dumping_pc") => {
                                    let total = metrics.num_peers_up_eor_capable.load(Ordering::SeqCst);
                                    let v = metrics.num_peers_up_dumping.load(Ordering::SeqCst);
                                    calc_u8_pc(total, v).into()
                                }

                                Some("invalid_messages") => {
                                    if self.bmp_in_metrics.contains(&router_id) {
                                        self.bmp_in_metrics.router_metrics(router_id.clone()).num_invalid_bmp_messages.load(Ordering::SeqCst)
                                    } else {
                                        0
                                    }
                                }

                                Some("soft_parse_errors") => {
                                    metrics.num_bgp_updates_with_recoverable_parsing_failures_for_known_peers.load(Ordering::SeqCst) +
                                    metrics.num_bgp_updates_with_recoverable_parsing_failures_for_unknown_peers.load(Ordering::SeqCst)
                                }

                                Some("hard_parse_errors") => {
                                    metrics.num_bgp_updates_with_unrecoverable_parsing_failures_for_known_peers.load(Ordering::SeqCst) +
                                    metrics.num_bgp_updates_with_unrecoverable_parsing_failures_for_unknown_peers.load(Ordering::SeqCst)
                                }

                                _ => unreachable!()
                            }
                        } else {
                            0
                        };

                        sort_tmp.push((resolved_v, *addr));
                    }
                }

                sort_tmp.sort_unstable_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
                sort_tmp.iter().map(|(_k, v)| *v).collect()
            }

            Some(other) => {
                return Err(format!(
                    "Unknown value '{}' for query parameter 'sort_by'",
                    other
                ));
            }
        };

        match sort_order.as_ref().map(MatchedParam::value) {
            None | Some("asc") => { /* nothing to do */ }

            Some("desc") => keys.reverse(),

            Some(other) => {
                return Err(format!(
                    "Unknown value '{}' for query parameter 'sort_order'",
                    other
                ));
            }
        }

        Ok(keys)
    }
}
