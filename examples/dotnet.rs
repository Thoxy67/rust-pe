use rust_pe::reflective_loader_with_args;

fn main() {
    let data = include_bytes!("hello_dot_net.exe");

    // Load and execute the .NET assembly with arguments
    unsafe {
        reflective_loader_with_args(data, &["hello", "from", "rspe"]);
    }
}
