use allocator_api2::alloc::{Allocator, Layout, System};

use std::{
    alloc::GlobalAlloc,
    sync::atomic::{AtomicUsize, Ordering::SeqCst},
};

use crate::metrics::{self, Metric, MetricType, MetricUnit};

static BYTES_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
pub static ALLOCATOR: TrackingAllocator<System> = TrackingAllocator { allocator: System };

// ---

#[derive(Copy, Clone, Debug, Default)]
pub struct Stats {
    pub bytes_allocated: usize,
}

// ---

#[derive(Clone, Debug)]
pub struct TrackingAllocator<T: Allocator> {
    allocator: T,
}

// ---

impl<T: Allocator> TrackingAllocator<T> {
    pub fn new(allocator: T) -> Self {
        Self { allocator }
    }

    pub fn allocator(&self) -> &T {
        &self.allocator
    }

    pub fn reset(&self) {
        BYTES_ALLOCATED.store(0, SeqCst);
    }

    pub fn record_alloc(&self, layout: Layout) {
        BYTES_ALLOCATED.fetch_add(layout.size(), SeqCst);
    }

    pub fn record_dealloc(&self, layout: Layout) {
        BYTES_ALLOCATED.fetch_sub(layout.size(), SeqCst);
    }

    pub fn stats(&self) -> Stats {
        Stats {
            bytes_allocated: BYTES_ALLOCATED.load(SeqCst),
        }
    }
}

// ---

impl Default for TrackingAllocator<System> {
    fn default() -> Self {
        Self { allocator: System }
    }
}

// ---

unsafe impl<T: Allocator> Allocator for TrackingAllocator<T> {
    fn allocate(
        &self,
        layout: Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, allocator_api2::alloc::AllocError> {
        let p = self.allocator.allocate(layout);
        self.record_alloc(layout);
        p
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, layout: Layout) {
        self.allocator.deallocate(ptr, layout);
        self.record_dealloc(layout);
    }
}

// ---

unsafe impl<T: Allocator + GlobalAlloc> GlobalAlloc for TrackingAllocator<T> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = self.allocator.alloc(layout);
        self.record_alloc(layout);
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.allocator.dealloc(ptr, layout);
        self.record_dealloc(layout);
    }
}

// ---

impl<T: Allocator> TrackingAllocator<T> {
    const NUM_BYTES_ALLOCATED_METRIC: Metric = Metric::new(
        "tracking_allocator_num_bytes_allocated",
        "the amount of memory currently allocated",
        MetricType::Gauge,
        MetricUnit::Total,
    );
}

impl<T: Allocator + Send + Sync> metrics::Source for TrackingAllocator<T> {
    fn append(&self, unit_name: &str, target: &mut metrics::Target) {
        let stats = ALLOCATOR.stats();

        target.append_simple(
            &Self::NUM_BYTES_ALLOCATED_METRIC,
            Some(unit_name),
            stats.bytes_allocated,
        );
    }
}
