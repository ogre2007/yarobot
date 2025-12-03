use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use stringzz::{
    extract_and_count_ascii_strings, extract_and_count_utf16_strings, extract_opcodes,
    FileProcessor,
};

// Helper to load test data
fn load_test_data() -> Vec<u8> {
    include_bytes!("../tests/fixtures/strings_test.bin").to_vec()
}

fn load_large_test_data() -> Vec<u8> {
    // You can create or use a larger test file
    let mut data = Vec::new();
    for i in 0..1024 * 1024 {
        // 1MB of test data
        data.push((i % 95 + 32) as u8); // Printable ASCII
        if i % 100 == 0 {
            data.extend_from_slice(&[0, 0, 0, 0]); // Some nulls
        }
    }
    data
}

// Benchmarks for ASCII string extraction
fn bench_ascii_extraction(c: &mut Criterion) {
    let data = load_test_data();
    let large_data = load_large_test_data();

    let mut group = c.benchmark_group("ascii_extraction");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);

    // Test with different min lengths
    for min_len in [3, 5, 8].iter() {
        group.bench_with_input(
            BenchmarkId::new("test_file", min_len),
            min_len,
            |b, &min_len| b.iter(|| extract_and_count_ascii_strings(&data, min_len, 128)),
        );

        group.bench_with_input(
            BenchmarkId::new("large_file", min_len),
            min_len,
            |b, &min_len| b.iter(|| extract_and_count_ascii_strings(&large_data, min_len, 128)),
        );
    }

    group.finish();
}

// Benchmarks for UTF-16 string extraction
fn bench_utf16_extraction(c: &mut Criterion) {
    // Create UTF-16 test data
    let mut utf16_data = Vec::new();
    let test_string = "Hello World!".encode_utf16().collect::<Vec<u16>>();

    // Repeat the string many times
    for _ in 0..10000 {
        for &code_unit in &test_string {
            utf16_data.extend_from_slice(&code_unit.to_le_bytes());
        }
        // Add some nulls
        utf16_data.extend_from_slice(&[0, 0, 0, 0]);
    }

    let mut group = c.benchmark_group("utf16_extraction");

    group.bench_function("utf16_small", |b| {
        b.iter(|| extract_and_count_utf16_strings(&utf16_data, 5, 128))
    });

    group.finish();
}

// Benchmarks for opcode extraction
fn bench_opcode_extraction(c: &mut Criterion) {
    // You'll need some actual PE/ELF/DEX files for testing
    let pe_data = include_bytes!("../tests/fixtures/test.exe.bin").to_vec();
    let elf_data = include_bytes!("../tests/fixtures/sample.elf").to_vec();

    let mut group = c.benchmark_group("opcode_extraction");

    if !pe_data.is_empty() {
        group.bench_function("pe_opcodes", |b| {
            b.iter(|| extract_opcodes(pe_data.clone()).unwrap())
        });
    }

    if !elf_data.is_empty() {
        group.bench_function("elf_opcodes", |b| {
            b.iter(|| extract_opcodes(elf_data.clone()).unwrap())
        });
    }

    group.finish();
}

// Benchmarks for file processing
fn bench_file_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_processing");

    group.bench_function("process_small_file", |b| {
        b.iter(|| {
            let mut processor = FileProcessor::default();
            processor.process_file_with_checks("tests/fixtures/test.exe.bin".to_string())
        })
    });

    group.finish();
}

// Benchmarks for memory usage (peak allocation)
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    // Use Criterion's built-in memory measurement
    group.bench_function("deduplicate_strings", |b| {
        let mut processor = FileProcessor::default();
        processor.config.min_string_len = 10;
        // Add some test data
        for i in 0..10000 {
            processor.strings.insert(
                format!("string_{}", i),
                stringzz::TokenInfo::new(
                    format!("string_{}", i),
                    1,
                    stringzz::TokenType::ASCII,
                    std::collections::HashSet::new(),
                    None,
                ),
            );
        }

        b.iter(|| processor.deduplicate_strings())
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(10))
        .sample_size(100)
        .nresamples(1000);
    targets =
        bench_ascii_extraction,
        bench_utf16_extraction,
        bench_opcode_extraction,
        bench_file_processing,
        bench_memory_usage
);

criterion_main!(benches);
