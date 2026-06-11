//! Connects to the spot network and exercises the basic client features:
//! `cargo run --example spot_test`

use std::time::Duration;

fn main() {
    let t = Duration::from_secs(30);

    println!("creating client...");
    let client = spotlib::Client::new().expect("failed to create client");
    println!("local address: {}", client.target_id());

    println!("waiting to come online...");
    client.wait_online(t).expect("failed to come online");
    let (conns, online) = client.connection_count();
    println!("online ({online}/{conns} connections)");

    let now = client.get_time(t).expect("failed to get server time");
    println!("server time: {now:?}");

    // query our own ping endpoint through the network (E2E encrypted)
    let target = format!("{}/ping", client.target_id());
    let res = client
        .query(&target, b"hello self!", t)
        .expect("self ping failed");
    println!(
        "self ping response: {:?}",
        String::from_utf8_lossy(&res)
    );

    // fetch our own ID card
    let res = client
        .query(&format!("{}/version", client.target_id()), b"", t)
        .expect("self version failed");
    println!("self version: {}", String::from_utf8_lossy(&res));

    println!("all good");
}
