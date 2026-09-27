//! Client su dataset reale: scarica il DB dal backend, verifica la root contro
//! il manifest, scansiona query etichettate (match/ e nomatch/) con tutte le strategie.
//! Uso:
//!   cargo run --release --bin e2e_dataset -- --make-queries   (una tantum)
//!   cargo run --release --bin e2e_dataset                     (benchmark)
use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use frontend::comparison::{build_strategy, ComparisonContext, ComparisonStrategy};
use hash_engine::db_merkle::{db_merkle_root, merkle_path};
use hash_engine::compute_pdq_from_image;
use image::{DynamicImage, GenericImageView, ImageBuffer, ImageOutputFormat, Rgba};
use serde::Deserialize;

const BASE: &str = "https://127.0.0.1:3000";
const TOKEN: &str = "Bearer super-secret-device-token-123";
const T: u32 = 30;
const DB_IMAGES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../hash-engine/tests/images");
const DATASET: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../dataset");

#[derive(Deserialize)]
struct Manifest {
    version: String,
    db_hash: String,
}

#[derive(Deserialize)]
struct DownloadedDb {
    version: String,
    hashes: Vec<String>,
}

#[derive(Default)]
struct Stats {
    prove: Vec<Duration>,
    verify: Vec<Duration>,
    net: Vec<Duration>,
    ok: u32,
}

fn avg(v: &[Duration]) -> Duration {
    if v.is_empty() { Duration::ZERO } else { v.iter().sum::<Duration>() / v.len() as u32 }
}

fn hamming(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn save_jpeg(img: &DynamicImage, path: &str, q: u8) -> Result<(), Box<dyn std::error::Error>> {
    let f = std::fs::File::create(path)?;
    img.write_to(&mut std::io::BufWriter::new(f), ImageOutputFormat::Jpeg(q))?;
    Ok(())
}

fn sorted_images(dir: &str) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    v.retain(|p| p.is_file());
    v.sort();
    v
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--make-queries-oos") {
        let out_dir = format!("{}/queries/match", DATASET);
        std::fs::create_dir_all(&out_dir)?;
        for p in sorted_images(DB_IMAGES) {
            let stem = p.file_stem().unwrap().to_string_lossy().to_string();
            let img = image::open(&p)?;
            let (w, h) = img.dimensions();
            // 1. rotazione 90° (nessuna rotazione è indicizzata)
            let rot = DynamicImage::ImageRgba8(image::imageops::rotate90(&img));
            save_jpeg(&rot, &format!("{}/{}_rot90.jpg", out_dir, stem), 80)?;
            // 2. flip verticale (nel set c'è solo quello orizzontale)
            let fv = img.flipv();
            save_jpeg(&fv, &format!("{}/{}_flipv.jpg", out_dir, stem), 80)?;
            // 3. crop asimmetrico: 20% solo da sinistra (i crop indicizzati sono centrati)
            let mut tmp = img.clone();
            let acrop = DynamicImage::ImageRgba8(
                image::imageops::crop(&mut tmp, (w as f32 * 0.20) as u32, 0, (w as f32 * 0.80) as u32, h).to_image(),
            );
            save_jpeg(&acrop, &format!("{}/{}_acrop.jpg", out_dir, stem), 80)?;
        }
        println!("Query out-of-set generate in {}", out_dir);
        return Ok(());
    }
    // --- Utility una-tantum: genera query "match" (trasformazioni NON presenti nel DB) ---
    if std::env::args().any(|a| a == "--make-queries") {
        let out_dir = format!("{}/queries/match", DATASET);
        std::fs::create_dir_all(&out_dir)?;
        for p in sorted_images(DB_IMAGES) {
            let stem = p.file_stem().unwrap().to_string_lossy().to_string();
            let img = image::open(&p)?;
            let (w, h) = img.dimensions();
            // crop centrale 92% + JPEG 65
            let (cw, ch) = ((w as f32 * 0.92) as u32, (h as f32 * 0.92) as u32);
            let mut tmp = img.clone();
            let cropped = DynamicImage::ImageRgba8(
                image::imageops::crop(&mut tmp, (w - cw) / 2, (h - ch) / 2, cw, ch).to_image(),
            );
            save_jpeg(&cropped, &format!("{}/{}_crop65.jpg", out_dir, stem), 65)?;
            // scale 85% + JPEG 80
            let scaled = img.resize((w as f32 * 0.85) as u32, (h as f32 * 0.85) as u32, image::imageops::FilterType::Lanczos3);
            save_jpeg(&scaled, &format!("{}/{}_scale85.jpg", out_dir, stem), 80)?;
            println!("  [queries] {} → 2 query", stem);
        }
        println!("Query match generate in {}. Copia foto NON correlate in {}/queries/nomatch/", out_dir, DATASET);
        return Ok(());
    }

    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;

    // --- FASE A: download DB + verifica root ricalcolata contro manifest.db_hash ---
    let manifest: Manifest = client.get(format!("{}/api/v1/hashes/manifest", BASE))
        .header("Authorization", TOKEN).send().await?.json().await?;
    let dl: DownloadedDb = client.get(format!("{}/api/v1/hashes/download", BASE))
        .header("Authorization", TOKEN).send().await?.json().await?;
    let flat: Vec<[u8; 32]> = dl.hashes.iter()
        .map(|h| Ok::<_, Box<dyn std::error::Error>>(hex::decode(h)?[..32].try_into()?))
        .collect::<Result<_, _>>()?;
    let root = db_merkle_root(&flat);
    assert_eq!(hex::encode(root), manifest.db_hash, "root ricalcolata != db_hash del manifest");
    println!("✓ DB scaricato ({}): {} hash, depth={} — root verificata contro manifest\n",
             manifest.version, flat.len(), flat.len().ilog2());

    // --- Strategie costruite UNA volta sola ---
    let modes = ["baseline", "zkp", "zkp-membership", "phe"];
    let strategies: Vec<(&'static str, Box<dyn ComparisonStrategy>)> = modes.iter()
        .map(|&m| Ok((m, build_strategy(m, flat.len())?)))
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;

    // --- FASE B: query etichettate ---
    let mut queries: Vec<(std::path::PathBuf, bool)> = Vec::new();
    for (dir, label) in [(format!("{}/queries/match", DATASET), true), (format!("{}/queries/nomatch", DATASET), false)] {
        for p in sorted_images(&dir) { queries.push((p, label)); }
    }
    if queries.is_empty() {
        return Err(format!("Nessuna query trovata: lancia prima --make-queries e popola {}/queries/nomatch/", DATASET).into());
    }
    println!("Query: {} ({} match, {} nomatch)\n", queries.len(),
             queries.iter().filter(|(_, l)| *l).count(), queries.iter().filter(|(_, l)| !*l).count());

    let mut stats: HashMap<&str, Stats> = modes.iter().map(|&m| (m, Stats::default())).collect();
    let (mut tp, mut fp, mut fn_, mut tn) = (0u32, 0u32, 0u32, 0u32);

    for (path, label) in &queries {
        let img = image::open(path)?;
        let q = compute_pdq_from_image(&img)?;
        let (cand, dist) = flat.iter().enumerate()
            .map(|(i, h)| (i, hamming(&q.0, h)))
            .min_by_key(|&(_, d)| d).unwrap();
        let hit = dist <= T;
        match (label, hit) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (true, false) => fn_ += 1,
            (false, false) => tn += 1,
        }

        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !hit {
            println!("  {:<34} dH={:>3} → NoMatch (label={})", name, dist, label);
            continue;
        }

        let context = ComparisonContext {
            reference_hash: hash_engine::PdqHash(flat[cand]),
            threshold: T,
            db_root: root,
            merkle_path: merkle_path(&flat, cand),
        };

        for (mode, strategy) in strategies.iter() {
            let m = *mode;
            let t0 = Instant::now();
            let res = strategy.compare(&q, &context)?;
            let prove = t0.elapsed();
            let (mut verify, mut net) = (Duration::ZERO, Duration::ZERO);
            if let Some(proof) = &res.proof {
                let t1 = Instant::now();
                let _ = strategy.verify(proof, &context)?;
                verify = t1.elapsed();
                let builder = match m {
                    "zkp" => client.post(format!("{}/api/v1/scan/zkp", BASE)).json(&serde_json::json!({
                        "proof_b64": BASE64.encode(proof),
                        "verifying_key_b64": BASE64.encode(&strategy.verifying_key_bytes().unwrap()),
                        "reference_hash_hex": hex::encode(flat[cand]),
                        "threshold": T })),
                    "zkp-membership" => client.post(format!("{}/api/v1/scan/zkp-membership", BASE)).json(&serde_json::json!({
                        "proof_b64": BASE64.encode(proof),
                        "verifying_key_b64": BASE64.encode(&strategy.verifying_key_bytes().unwrap()),
                        "threshold": T })),
                    "phe" => client.post(format!("{}/api/v1/scan/phe", BASE)).json(&serde_json::json!({
                        "ciphertexts_b64": BASE64.encode(proof),
                        "decryption_key_b64": BASE64.encode(&strategy.decryption_key_bytes().unwrap()),
                        "reference_hash_hex": hex::encode(flat[cand]),
                        "threshold": T })),
                    _ => continue,
                };
                let t2 = Instant::now();
                let resp = builder.header("Authorization", TOKEN).send().await?;
                net = t2.elapsed();
                let s = stats.get_mut(m).unwrap();
                if resp.status().is_success() { s.ok += 1; } else { println!("    ERR {} → {}", m, resp.status()); }
            }
            let s = stats.get_mut(m).unwrap();
            s.prove.push(prove);
            s.verify.push(verify);
            s.net.push(net);
        }
        println!("  {:<34} dH={:>3} → Match (label={}) ✓", name, dist, label);
    }

    // --- FASE C: report ---
    println!("\n================ DATASET REPORT ================");
    println!("TP={}  FP={}  FN={}  TN={}", tp, fp, fn_, tn);
    if tp + fn_ > 0 { println!("Recall    = {:.1}%", 100.0 * tp as f32 / (tp + fn_) as f32); }
    if tp + fp > 0 { println!("Precision = {:.1}%", 100.0 * tp as f32 / (tp + fp) as f32); }
    println!("{:<16} {:>12} {:>12} {:>12} {:>6}", "strategy", "prove", "verify", "net RTT", "ok");
    for (mode, _) in strategies.iter() {
        let s = &stats[mode];
        println!("{:<16} {:>12?} {:>12?} {:>12?} {:>6}", mode, avg(&s.prove), avg(&s.verify), avg(&s.net), s.ok);
    }
    println!("=================================================");
    Ok(())
}