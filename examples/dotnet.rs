use rust_pe::reflective_loader_with_args;

fn main() {
    let data = include_bytes!("hello_dot_net.exe");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    unsafe {
        let _ = reflective_loader_with_args(data, &arg_refs);
    }
}
