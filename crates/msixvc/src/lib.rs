mod common;
mod crypt;
pub mod math;
pub mod models;
pub mod streaming;
pub mod streaming_ntfs;
pub mod xsp;
pub mod xvd;

#[cfg(test)]
mod bughunt_concurrency {
    use futures_util::{StreamExt, stream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // `xodus-cli streaming --parallel N` feeds N straight into for_each_concurrent.
    #[tokio::test]
    async fn parallel_zero_means_unlimited_not_serial() {
        for limit in [0usize, 2usize] {
            let live = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            stream::iter(0..50)
                .for_each_concurrent(limit, |_| {
                    let live = live.clone();
                    let peak = peak.clone();
                    async move {
                        let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(n, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        tokio::task::yield_now().await;
                        live.fetch_sub(1, Ordering::SeqCst);
                    }
                })
                .await;
            println!(
                "--parallel {limit} -> peak concurrency {}",
                peak.load(Ordering::SeqCst)
            );
        }
    }
}
