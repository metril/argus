//! Real-kernel check of `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` behind an nftables REDIRECT.
//!
//! Opt-in: set `ARGUS_KERNEL_TEST=1`. The test re-executes itself inside a throwaway
//! network namespace (`unshare -rn`, or `unshare -n` as root), brings up `lo`, loads a `nat`
//! ruleset there and asserts what the accepted socket reports. Nothing outside that namespace is
//! touched. Without the env var, without Linux, or without `unshare`/`ip`/`nft` (or the right to
//! create a namespace) the test prints why it was skipped and passes.

#![cfg(target_os = "linux")]

use proxy_core::transparent::{KernelOriginalDst, OriginalDst};
use std::net::SocketAddr;
use std::process::Command;

const TEST_NAME: &str = "kernel_original_dst_with_nftables_redirect";
const CHILD_ENV: &str = "ARGUS_KERNEL_CHILD";

fn skip(why: &str) {
    eprintln!("SKIPPED {TEST_NAME}: {why}");
}

fn works(cmd: &[&str]) -> bool {
    Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:").map(str::to_owned))
        })
        .is_some_and(|l| l.split_whitespace().nth(1) == Some("0"))
}

#[test]
fn kernel_original_dst_with_nftables_redirect() {
    if std::env::var_os(CHILD_ENV).is_some() {
        return child();
    }
    if common::env::var_os("KERNEL_TEST").is_none() {
        return skip("opt-in; set ARGUS_KERNEL_TEST=1");
    }
    for tool in [["unshare", "--version"], ["ip", "-V"], ["nft", "--version"]] {
        if !works(&tool) {
            return skip(&format!("`{}` not available", tool[0]));
        }
    }
    let ns: &[&str] = if works(&["unshare", "-rn", "true"]) {
        &["unshare", "-rn"]
    } else if is_root() && works(&["unshare", "-n", "true"]) {
        &["unshare", "-n"]
    } else {
        return skip("cannot create a network namespace (not root, user namespaces disabled)");
    };

    let out = Command::new(ns[0])
        .args(&ns[1..])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn namespaced child");
    assert!(
        out.status.success(),
        "namespaced child failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Runs inside the new network namespace.
fn child() {
    let sh = |cmd: &str, stdin: Option<&str>| {
        use std::io::Write;
        let mut c = Command::new("sh");
        c.args(["-c", cmd]);
        if stdin.is_some() {
            c.stdin(std::process::Stdio::piped());
        }
        let mut child = c.spawn().expect("sh");
        if let Some(s) = stdin {
            child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
        }
        assert!(child.wait().unwrap().success(), "failed: {cmd}");
    };
    sh("ip link set lo up", None);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // One dual-stack listener, as `host = "::"` would give: IPv4 redirects arrive v4-mapped.
        let (listener, v6) = match tokio::net::TcpListener::bind("[::]:0").await {
            Ok(l) => (l, true),
            Err(_) => (tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap(), false),
        };
        let port = listener.local_addr().unwrap().port();
        sh(
            "nft -f -",
            Some(&format!(
                "table inet adblock_test {{\n chain out {{ type nat hook output priority -100; policy accept;\n  ip daddr 127.0.0.0/8 tcp dport 9999 redirect to :{port}\n  ip6 daddr ::1 tcp dport 9998 redirect to :{port}\n }}\n}}\n"
            )),
        );

        let mut cases: Vec<SocketAddr> = vec![
            "127.0.0.1:9999".parse().unwrap(),
            "127.0.0.2:9999".parse().unwrap(),
        ];
        if v6 {
            cases.push("[::1]:9998".parse().unwrap());
        }
        for want in cases {
            // Nothing listens on `want`; only the redirect can make this connect succeed.
            let client = tokio::spawn(tokio::net::TcpStream::connect(want));
            let (accepted, peer) = listener.accept().await.unwrap();
            let got = KernelOriginalDst
                .original_dst(&accepted)
                .await
                .unwrap_or_else(|e| panic!("original_dst for {want}: {e}"));
            assert_eq!(got.ip().to_canonical(), want.ip(), "peer {peer}");
            assert_eq!(got.port(), want.port());
            drop(client.await.unwrap().expect("redirected connect"));
        }

        // A client that dials the listener directly (not redirected): the kernel either has no
        // original destination (error) or reports the listener itself; either way the proxy
        // refuses it (error, or the loop guard).
        let direct = tokio::spawn(tokio::net::TcpStream::connect(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
        let (accepted, _) = listener.accept().await.unwrap();
        match KernelOriginalDst.original_dst(&accepted).await {
            Err(_) => {}
            Ok(dst) => assert!(
                proxy_core::transparent::is_self(dst, accepted.local_addr().unwrap(), &[port]),
                "direct connection reported {dst}"
            ),
        }
        drop(direct.await.unwrap());
        eprintln!("kernel original-dst checks passed (ipv6 cases: {v6})");
    });
}
