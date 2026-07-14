//! Diagnostic criterion benches for ADR-0010 rotating admission.
//!
//! Not a performance qualification artifact: measures relative shape of
//! admit/claim/commit with page rotation and quota refusal only. Zero
//! steady-state allocation after channel construction is asserted by the
//! unit suite (`rotation_reuses_pool_slots_beyond_capacity`); these benches
//! compile under CI (`--no-run`) like the other `aegis-event` diagnostics.

use aegis_event::{
    RotatingAdmissionChannel, SlabPageConfig, TryRotatingAdmitError, TryRotatingConsumeError,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

const PAYLOAD: [u8; 64] = [0x5a; 64];

fn page_config(descriptor_capacity: usize, first_sequence: u64) -> SlabPageConfig {
    SlabPageConfig {
        arena_id: 1,
        arena_generation: 0,
        byte_capacity: PAYLOAD.len() * descriptor_capacity,
        descriptor_capacity,
        first_sequence,
    }
}

/// Single-page-capacity channel: every admit after the first rotates.
/// Same-thread producer+consumer so rotation seams stay in the measured path.
fn rotating_admit_claim_commit_with_rotation(c: &mut Criterion) {
    c.bench_function(
        "rotating_admission_64b_claim_commit_with_rotation_diagnostic",
        |b| {
            b.iter_batched(
                || {
                    RotatingAdmissionChannel::<8, 4>::new(page_config(1, 0))
                        .expect("benchmark rotating channel is valid")
                        .split()
                },
                |(mut producer, mut consumer)| {
                    // Two admits force at least one rotation (descriptor_capacity=1).
                    let t0 = producer
                        .try_admit(black_box(&PAYLOAD), 1, 0)
                        .expect("epoch 0 admit");
                    let t1 = producer
                        .try_admit(black_box(&PAYLOAD), 1, 0)
                        .expect("epoch 1 rotate+admit");
                    let f0 = consumer.try_next().expect("epoch 0 frame");
                    black_box(f0.payload());
                    let c0 = f0.commit();
                    let f1 = consumer.try_next().expect("epoch 1 frame");
                    black_box(f1.payload());
                    let c1 = f1.commit();
                    black_box((t0, t1, c0, c1));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

/// Full pool (P live epochs) → typed `PageQuotaExhausted` with no mutation.
fn rotating_quota_exhaustion_rejection(c: &mut Criterion) {
    c.bench_function("rotating_admission_page_quota_exhausted_diagnostic", |b| {
        b.iter_batched(
            || {
                let channel = RotatingAdmissionChannel::<8, 2>::new(page_config(1, 0))
                    .expect("benchmark rotating channel is valid");
                let (mut producer, consumer) = channel.split();
                // Fill both pool slots (P=2, capacity 1 each).
                producer
                    .try_admit(&PAYLOAD, 1, 0)
                    .expect("epoch 0 occupies slot 0");
                producer
                    .try_admit(&PAYLOAD, 1, 0)
                    .expect("epoch 1 occupies slot 1");
                (producer, consumer)
            },
            |(mut producer, _consumer)| {
                let result = producer.try_admit(black_box(&PAYLOAD), 1, 0);
                assert!(matches!(
                    result,
                    Err(TryRotatingAdmitError::PageQuotaExhausted {
                        live_epochs: 2,
                        pool: 2
                    })
                ));
                let _ = black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Steady same-thread round trip across many rotations (pool rebind path).
fn rotating_multi_epoch_round_trip(c: &mut Criterion) {
    c.bench_function(
        "rotating_admission_multi_epoch_round_trip_diagnostic",
        |b| {
            b.iter_batched(
                || {
                    RotatingAdmissionChannel::<16, 2>::new(page_config(1, 0))
                        .expect("benchmark rotating channel is valid")
                        .split()
                },
                |(mut producer, mut consumer)| {
                    // Six events over P=2 forces slot reuse (epochs 0..5).
                    for i in 0u8..6 {
                        let payload = [i; 64];
                        loop {
                            match producer.try_admit(black_box(&payload), 1, 0) {
                                Ok(_) => break,
                                Err(TryRotatingAdmitError::PageQuotaExhausted { .. }) => {
                                    let frame = consumer
                                        .try_next()
                                        .expect("drain lagging consumer under quota");
                                    black_box(frame.payload());
                                    frame.commit();
                                }
                                Err(error) => panic!("unexpected admit error: {error}"),
                            }
                        }
                    }
                    producer.finish().expect("clean finish");
                    loop {
                        match consumer.try_next() {
                            Ok(frame) => {
                                black_box(frame.payload());
                                frame.commit();
                            }
                            Err(TryRotatingConsumeError::CleanEnd) => break,
                            Err(TryRotatingConsumeError::Empty) => continue,
                            Err(error) => panic!("unexpected drain error: {error}"),
                        }
                    }
                    black_box(consumer.total_committed());
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(
    benches,
    rotating_admit_claim_commit_with_rotation,
    rotating_quota_exhaustion_rejection,
    rotating_multi_epoch_round_trip
);
criterion_main!(benches);
