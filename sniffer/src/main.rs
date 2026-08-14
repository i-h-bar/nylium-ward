mod net;
mod parser;

// Capture loop goes here in a later segment, once `parser` is done and we've
// moved on to reading real bytes off the wire instead of test fixtures.
fn main() {
    println!("mc-sniffer: parser segment only — no capture loop yet");
}
