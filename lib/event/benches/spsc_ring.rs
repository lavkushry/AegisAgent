use aegis_event::{SpscRing, TelemetryDescriptor, TryPopError};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn same_thread_round_trip(c: &mut Criterion) {
    let ring = SpscRing::<u64, 1024>::new().expect("benchmark capacity is valid");
    let (mut producer, mut consumer) = ring.split();

    c.bench_function("spsc_u64_same_thread_round_trip", |b| {
        let mut sequence = 0_u64;
        b.iter(|| {
            producer
                .try_push(sequence)
                .expect("one push followed by one pop cannot fill the ring");
            let value = match consumer.try_pop() {
                Ok(value) => value,
                Err(TryPopError::Empty | TryPopError::Disconnected) => {
                    panic!("published value must be available")
                }
            };
            sequence = sequence.wrapping_add(1);
            black_box(value)
        });
    });
}

fn descriptor_same_thread_round_trip(c: &mut Criterion) {
    let ring = SpscRing::<TelemetryDescriptor, 1024>::new().expect("benchmark capacity is valid");
    let (mut producer, mut consumer) = ring.split();

    c.bench_function("spsc_descriptor_same_thread_round_trip", |b| {
        let mut descriptor = TelemetryDescriptor {
            sequence: 0,
            arena_generation: 1,
            arena_id: 1,
            flags: 0,
            offset: 0,
            len: 256,
            crc32c: 0,
            schema_id: 1,
        };
        b.iter(|| {
            producer
                .try_push(descriptor)
                .expect("one push followed by one pop cannot fill the ring");
            let value = match consumer.try_pop() {
                Ok(value) => value,
                Err(TryPopError::Empty | TryPopError::Disconnected) => {
                    panic!("published descriptor must be available")
                }
            };
            descriptor.sequence = descriptor.sequence.wrapping_add(1);
            black_box(value)
        });
    });
}

criterion_group!(
    benches,
    same_thread_round_trip,
    descriptor_same_thread_round_trip
);
criterion_main!(benches);
