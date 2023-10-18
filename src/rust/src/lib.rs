use curve_trees::tests::bench_membership;

#[cxx::bridge]
mod ffi {
    // Rust types and signatures exposed to C++.
    extern "Rust" {
        #[namespace = "monero_rust::curve_trees"]
        fn run_bench_membership();
    }
}

pub fn run_bench_membership() {
    bench_membership::bench_membership();
}
