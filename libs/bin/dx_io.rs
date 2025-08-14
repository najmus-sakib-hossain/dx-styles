fn main() {
    if let Err(e) = dx::io::dx_io() {
        eprintln!("dx_io failed: {}", e);
    }
}
