use aegis_event::{PublishedSlabPage, SlabPageConfig};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

const PAYLOAD: [u8; 256] = [0xa5; 256];

fn append_and_resolve(c: &mut Criterion) {
    c.bench_function("published_slab_256b_append_and_resolve_diagnostic", |b| {
        b.iter_batched(
            || {
                let page = PublishedSlabPage::new(SlabPageConfig {
                    arena_id: 1,
                    arena_generation: 1,
                    byte_capacity: PAYLOAD.len(),
                    descriptor_capacity: 1,
                    first_sequence: 0,
                })
                .expect("benchmark page configuration is valid");
                page.split()
            },
            |(mut writer, reader)| {
                let descriptor = writer
                    .try_append(black_box(&PAYLOAD), 1, 0)
                    .expect("one preallocated frame fits");
                let payload = reader
                    .resolve(black_box(&descriptor))
                    .expect("published benchmark frame resolves");
                black_box(payload.as_ref());
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, append_and_resolve);
criterion_main!(benches);
