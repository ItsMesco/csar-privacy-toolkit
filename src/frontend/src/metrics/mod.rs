use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ComparisonMetrics {
    pub mode: String,
    pub latency_ns: u64,
    pub rss_delta_kb: i64,
}

#[derive(Default)]
pub struct MetricsCollector {
    samples: Vec<ComparisonMetrics>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    pub fn record(&mut self, m: ComparisonMetrics) {
        self.samples.push(m);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    fn sorted_latencies_ms(&self) -> Vec<f64> {
        let mut v: Vec<f64> = self
            .samples
            .iter()
            .map(|s| s.latency_ns as f64 / 1_000_000.0)
            .collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    }

    pub fn median_latency_ms(&self) -> f64 {
        percentile(&self.sorted_latencies_ms(), 0.5)
    }

    pub fn p95_latency_ms(&self) -> f64 {
        percentile(&self.sorted_latencies_ms(), 0.95)
    }

    pub fn mean_rss_delta_kb(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let sum: i64 = self.samples.iter().map(|s| s.rss_delta_kb).sum();
        sum as f64 / self.samples.len() as f64
    }

    pub fn report(&self) -> String {
        format!(
            "=== Benchmark Report (mode: {}) ===\n\
             Samples:               {}\n\
             Latency (median):      {:.3} ms\n\
             Latency (p95):         {:.3} ms\n\
             RSS delta (mean):      {:.1} KB (~{:.3} MB)\n",
            self.samples
                .first()
                .map(|s| s.mode.as_str())
                .unwrap_or("n/a"),
            self.len(),
            self.median_latency_ms(),
            self.p95_latency_ms(),
            self.mean_rss_delta_kb(),
            self.mean_rss_delta_kb() / 1024.0,
        )
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

/// Legge VmRSS corrente in KB.
#[cfg(target_os = "linux")]
pub fn current_rss_kb() -> i64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<i64>().ok())
        })
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
pub fn current_rss_kb() -> i64 {
    0 // fallback su piattaforme non-Linux, da estendere se serve
}

/// Esegue una comparazione misurando latenza e delta RSS.
pub fn measure<F>(mode: &str, f: F) -> (ComparisonMetrics, super::comparison::ComparisonResult)
where
    F: FnOnce() -> Result<super::comparison::ComparisonResult, super::comparison::ComparisonError>,
{
    let rss_before = current_rss_kb();
    let start = Instant::now();

    let result = f().expect("Comparison failed during measurement");

    let latency_ns = start.elapsed().as_nanos() as u64;
    let rss_after = current_rss_kb();

    let metrics = ComparisonMetrics {
        mode: mode.to_string(),
        latency_ns,
        rss_delta_kb: rss_after - rss_before,
    };

    (metrics, result)
}
