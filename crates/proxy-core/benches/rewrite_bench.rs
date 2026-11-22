//! Rewriter throughput (plain and per content-coding, decode + rewrite + encode) and the fixed
//! per-response cost (CSP parse + nonce + head build + rewriter setup).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use filter_engine::Cosmetics;
use proxy_core::csp::{self, Needs, PageOrigin, PolicyKind};
use proxy_core::inject::{build_head, new_nonce, PageSpec};
use proxy_core::internal::Internal;
use proxy_core::rewrite::codec::{decode_chain, Coding, DynBufRead, Encoder};
use proxy_core::rewrite::html::RewriteStage;
use proxy_core::rewrite::HtmlPlan;
use tokio::io::{AsyncBufReadExt, BufReader};

/// A realistic ~500 KB page: head with metas/links/scripts, nav, many articles, inline JSON.
fn page() -> Vec<u8> {
    let mut s = String::from(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Bench page</title>\
         <meta name=\"viewport\" content=\"width=device-width\"><link rel=\"stylesheet\" href=\"/a.css\">\
         <script async src=\"https://cdn.example/analytics.js\"></script>\
         <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}</script></head><body>\
         <nav><ul><li><a href=\"/\">Home</a></li><li><a href=\"/news\">News</a></li></ul></nav>",
    );
    let mut i = 0;
    while s.len() < 500 * 1024 {
        s.push_str(&format!(
            "<article class=\"post post-{i}\" id=\"p{i}\"><h2><a href=\"/post/{i}\">Headline number {i} of the day</a></h2>\
             <p class=\"lead\">Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore \
             et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris &amp; nisi ut aliquip.</p>\
             <img src=\"/img/{i}.jpg\" alt=\"photo {i}\" width=\"640\" height=\"360\" loading=\"lazy\">\
             <div class=\"meta\"><span>By Author {}</span> <time datetime=\"2026-01-01\">Jan 1</time></div>\
             <!-- end post {i} --></article>\n",
            i % 31
        ));
        if i % 25 == 0 {
            s.push_str("<script type=\"application/ld+json\">{\"@context\":\"https://schema.org\",\"@type\":\"Article\"}</script>\n");
        }
        i += 1;
    }
    s.push_str("</body></html>");
    s.into_bytes()
}

fn cosmetics() -> Cosmetics {
    Cosmetics {
        hide_selectors: (0..150)
            .map(|i| format!(".ad-slot-{i}, #banner-{i}, div[data-ad=\"{i}\"]"))
            .collect(),
        ..Default::default()
    }
}

fn plan(internal: &Internal) -> HtmlPlan {
    let cos = cosmetics();
    let head = build_head(&PageSpec {
        cosmetics: &cos,
        internal,
        host: "example.test",
        nonce: &new_nonce(),
        script_ok: true,
        observer_ok: true,
    });
    HtmlPlan {
        head_html: head.html,
        ..Default::default()
    }
}

/// The previous implementation's search: lowercase the buffer and scan for the anchors.
fn old_byte_search(chunks: &[&[u8]], payload: &[u8]) -> usize {
    let mut search: Vec<u8> = Vec::new();
    let mut out = 0usize;
    for c in chunks {
        search.extend_from_slice(c);
        let lower = search.to_ascii_lowercase();
        let pos = lower
            .windows(7)
            .position(|w| w == b"</head>")
            .or_else(|| lower.windows(5).position(|w| w == b"<body"));
        if pos.is_some() {
            out += search.len() + payload.len();
            search.clear();
            break;
        }
    }
    out
}

async fn pipeline(encoded: Vec<u8>, coding: Option<Coding>, plan: &HtmlPlan) -> usize {
    let input: DynBufRead = Box::pin(BufReader::new(std::io::Cursor::new(encoded)));
    let codings: Vec<Coding> = coding.into_iter().collect();
    let mut reader = decode_chain(input, &codings).await.unwrap();
    let mut stage = RewriteStage::new(plan, encoding_rs::UTF_8, false, 0).unwrap();
    let mut enc = Encoder::new(coding);
    let mut total = 0;
    loop {
        let buf = reader.fill_buf().await.unwrap();
        if buf.is_empty() {
            break;
        }
        let n = buf.len();
        let out = stage.push(buf).unwrap();
        reader.consume(n);
        enc.write(&out).await.unwrap();
        total += enc.take().len();
    }
    enc.write(&stage.finish().unwrap()).await.unwrap();
    total += enc.finish().await.unwrap().len();
    total
}

fn benches(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let internal = Internal::new();
    let html = page();
    let plan = plan(&internal);
    let bytes = html.len() as u64;

    let mut g = c.benchmark_group("rewrite_500kb");
    g.throughput(Throughput::Bytes(bytes));
    g.bench_function("old_byte_search_plain", |b| {
        let chunks: Vec<&[u8]> = html.chunks(16 * 1024).collect();
        b.iter(|| black_box(old_byte_search(&chunks, plan.head_html.as_bytes())))
    });
    g.bench_function("lol_html_plain", |b| {
        b.iter(|| {
            let mut stage = RewriteStage::new(&plan, encoding_rs::UTF_8, false, 0).unwrap();
            let mut n = 0;
            for ch in html.chunks(16 * 1024) {
                n += stage.push(ch).unwrap().len();
            }
            n += stage.finish().unwrap().len();
            black_box(n)
        })
    });
    for coding in [Coding::Gzip, Coding::Brotli, Coding::Zstd] {
        let encoded = rt.block_on(async {
            let mut e = Encoder::new(Some(coding));
            e.write(&html).await.unwrap();
            let mut v = e.take().to_vec();
            v.extend_from_slice(&e.finish().await.unwrap());
            v
        });
        g.bench_function(format!("decode_rewrite_encode_{}", coding.token()), |b| {
            b.iter(|| rt.block_on(pipeline(encoded.clone(), Some(coding), &plan)))
        });
    }
    g.finish();

    let mut f = c.benchmark_group("fixed_overhead");
    let origin = PageOrigin::new("https", "example.test", 443);
    let policy = "default-src 'self'; script-src 'self' 'nonce-abc' https://cdn.example.com https://*.google.com; \
                  style-src 'self' 'unsafe-inline'; img-src * data:; connect-src 'self' https://api.example.com; \
                  frame-ancestors 'self'; report-uri /csp";
    f.bench_function("csp_adapt", |b| {
        b.iter(|| {
            csp::adapt(
                black_box(policy),
                PolicyKind::Header,
                &origin,
                "NONCE",
                Needs {
                    script: true,
                    style: true,
                    connect: true,
                },
            )
        })
    });
    f.bench_function("nonce", |b| b.iter(new_nonce));
    let cos = Cosmetics {
        hide_selectors: vec![".ad".into(), "#banner".into()],
        ..Default::default()
    };
    f.bench_function("build_head_small", |b| {
        b.iter(|| {
            build_head(&PageSpec {
                cosmetics: &cos,
                internal: &internal,
                host: "example.test",
                nonce: "NONCE",
                script_ok: true,
                observer_ok: true,
            })
        })
    });
    let small = HtmlPlan {
        head_html: "<style>x</style>".into(),
        ..Default::default()
    };
    f.bench_function("rewriter_setup", |b| {
        b.iter(|| RewriteStage::new(&small, encoding_rs::UTF_8, false, 0).unwrap())
    });
    f.bench_function("total_per_response", |b| {
        b.iter(|| {
            let nonce = new_nonce();
            let a = csp::adapt(
                policy,
                PolicyKind::Header,
                &origin,
                &nonce,
                Needs {
                    script: true,
                    style: true,
                    connect: true,
                },
            );
            let head = build_head(&PageSpec {
                cosmetics: &cos,
                internal: &internal,
                host: "example.test",
                nonce: &nonce,
                script_ok: true,
                observer_ok: true,
            });
            let p = HtmlPlan {
                head_html: head.html,
                ..Default::default()
            };
            black_box((
                a,
                RewriteStage::new(&p, encoding_rs::UTF_8, false, 0).unwrap(),
            ))
        })
    });
    f.finish();
}

criterion_group!(rewrite, benches);
criterion_main!(rewrite);
