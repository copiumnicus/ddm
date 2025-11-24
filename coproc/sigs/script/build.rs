use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    let args = BuildArgs {
        rustflags: vec![
            "-Ccodegen-units=1".to_string(), // 5% improvement
            "-Cembed-bitcode=yes".to_string(),
            "-Clto=fat".to_string(), // 20% improvement!
        ],
        ..Default::default()
    };

    build_program_with_args("../program", args);
}
