use aegis_event::{SlabPageConfig, TryAdmitError, VolatileAdmissionChannel};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

const PAYLOAD: [u8; 256] = [0xa5; 256];

fn admit_claim_commit(c: &mut Criterion) {
    c.bench_function("volatile_admission_256b_claim_commit_diagnostic", |b| {
        b.iter_batched(
            || {
                VolatileAdmissionChannel::<2>::new(SlabPageConfig {
                    arena_id: 1,
                    arena_generation: 1,
                    byte_capacity: PAYLOAD.len(),
                    descriptor_capacity: 1,
                    first_sequence: 0,
                })
                .expect("benchmark channel configuration is valid")
                .split()
            },
            |(mut producer, mut consumer)| {
                let token = producer
                    .try_admit(black_box(&PAYLOAD), 1, 0)
                    .expect("one preallocated event fits");
                let frame = consumer
                    .try_next()
                    .expect("admitted benchmark frame validates");
                black_box(frame.payload());
                let committed = frame.commit();
                black_box((token, committed));
            },
            BatchSize::SmallInput,
        );
    });
}

fn saturated_rejection(c: &mut Criterion) {
    c.bench_function("volatile_admission_full_rejection_diagnostic", |b| {
        b.iter_batched(
            || {
                let channel = VolatileAdmissionChannel::<1>::new(SlabPageConfig {
                    arena_id: 1,
                    arena_generation: 1,
                    byte_capacity: PAYLOAD.len() * 2,
                    descriptor_capacity: 2,
                    first_sequence: 0,
                })
                .expect("benchmark channel configuration is valid");
                let (mut producer, consumer) = channel.split();
                producer
                    .try_admit(&PAYLOAD, 1, 0)
                    .expect("first event occupies the ring");
                (producer, consumer)
            },
            |(mut producer, _consumer)| {
                let result = producer.try_admit(black_box(&PAYLOAD), 1, 0);
                assert_eq!(result, Err(TryAdmitError::RingFull));
                let _ = black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, admit_claim_commit, saturated_rejection);
criterion_main!(benches);
