use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;
use std::vec;

use fs2::available_space;
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::models::xvd::PAGE_SIZE;
use msixvc::streaming;
use msixvc::xvd::{SegmentFile, XvdFile};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncSeekExt};
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::{get_content_id, get_packages};

struct Job {
    name: String,
    content: SegmentFile,
}

enum ProgressEvent {
    Started { id: usize, name: String, total: u64 },
    Advanced { id: usize, delta: u64 },
    Finished { id: usize },
    UpdateRemaining { name: String, total: u64 },
    UpdateStatus { name: String },
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
) -> ExitCode {
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    let ok = if source.starts_with("file://") {
        let fsrc = source.strip_prefix("file://").unwrap_or_default();
        let f = File::open(fsrc).await.unwrap();
        let l = f.metadata().await.unwrap().len();
        run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            f,
            l,
            &source,
            &tx,
            rx,
        )
        .await
    } else {
        let vurl = if source.starts_with("http://") || source.starts_with("https://") {
            source
        } else {
            let content_id = if Uuid::try_parse(&source).is_err() {
                let content_id_task = get_content_id(client, source, market.clone()).await;
                let Ok(content_id) = content_id_task else {
                    let Err(err) = content_id_task else {
                        eprintln!("Unknown Error");
                        return ExitCode::FAILURE;
                    };
                    eprintln!("{}", err);
                    return ExitCode::FAILURE;
                };
                content_id
            } else {
                source
            };
            let package_result = get_packages(client, tokens, content_id.clone()).await;
            let Ok(package) = package_result else {
                let Err(err) = package_result else {
                    eprintln!("Unknown Error");
                    return ExitCode::FAILURE;
                };
                eprintln!("{}", err);
                return ExitCode::FAILURE;
            };
            let Some(file) = package
                .package_files
                .iter()
                .find(|p| p.file_name.ends_with(".msixvc"))
            else {
                eprintln!("No .msixvc file found");
                return ExitCode::FAILURE;
            };
            format!(
                "{}{}",
                file.cdn_root_paths.first().unwrap(),
                file.relative_url
            )
        };
        let url = &vurl;
        let mut pos = 0;
        let http_file = streaming::HttpRead::open(
            client.clone(),
            url,
            Some(|c, _| {
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id: usize::MAX,
                        delta: c - pos,
                    })
                    .is_ok()
                {
                    pos = c;
                }
            }),
        )
        .await
        .expect("ok");
        let l = http_file.len();

        run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            http_file,
            l,
            url,
            &tx,
            rx,
        )
        .await
    };

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn run_cli_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
    mut rx: Receiver<ProgressEvent>,
) -> bool
where
    Reader: AsyncRead + Unpin,
{
    tokio::spawn(async move {
        let multi_progress = MultiProgress::new();
        let total_progess = multi_progress.add(ProgressBar::new(l).with_style(
            ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
            .progress_chars("#>-")
        ));

        total_progess.set_message("Initializing");
        let mut bars: HashMap<usize, ProgressBar> = HashMap::new();
        let mut last_print = std::time::Instant::now();

        while let Some(event) = rx.recv().await {
            match event {
                ProgressEvent::Started { id, name, total } => {
                    let cur_progess = multi_progress.add(ProgressBar::new(total).with_style(
                        ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
                        .progress_chars("#>-")
                    ));
                    cur_progess.set_message(name);
                    bars.insert(id, cur_progess);
                }
                ProgressEvent::Advanced { id, delta } => {
                    if let Some(bar) = bars.get(&id) {
                        bar.inc(delta);
                    }
                    total_progess.inc(delta);

                    let elapsed = last_print.elapsed();
                    if elapsed.as_millis() > 200 {
                        let pos = total_progess.position();
                        let len = total_progess.length().unwrap_or(pos.max(1));
                        let percent = (pos as f64 / len as f64 * 100.0) as u8;
                        
                        let bytes_per_sec = (total_progess.position() as f64 / total_progess.elapsed().as_secs_f64()) as u64;

                        // Print raw progress for Heroic's non-TTY parser with speed
                        println!("HEROIC_PROGRESS {}/{} {}% {}", pos, len, percent, bytes_per_sec);
                        last_print = std::time::Instant::now();
                    }
                }
                ProgressEvent::Finished { id } => {
                    if let Some(bar) = bars.remove(&id) {
                        bar.finish_and_clear();
                    }
                }
                ProgressEvent::UpdateRemaining { name, total } => {
                    total_progess.set_message(name);
                    total_progess.set_length(total_progess.position() + total);
                }
                ProgressEvent::UpdateStatus { name } => {
                    total_progess.set_message(name);
                }
            }
        }

        total_progess.abandon();
    });
    run_reader(
        client,
        tokens,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        reader,
        l,
        url,
        tx,
    )
    .await
}

async fn run_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
) -> bool
where
    Reader: AsyncRead + Unpin,
{
    let out: &Path = Path::new(&destination);

    std::fs::create_dir_all(out).expect("ok");

    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = streaming::PrefixCacheFile::new(reader, l, cache_path.clone())
        .await
        .expect("no err");
    let remote_xvd = XvdFile::parse(&mut remote_file).await.expect("no err");
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let files = remote_xvd
        .parse_user_package_files(&mut remote_file)
        .await
        .expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = remote_xvd
                .parse_segment_metadata(&mut remote_file, v)
                .await
                .expect("ok");
            rfiles = sfiles;
        }
    }

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file, !rfiles.is_empty())
            .await
            .expect("ok");
        rfiles.extend(sfiles);
    }

    let file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .ok();

    if let Some(mut file) = file {
        let xvd = XvdFile::parse(&mut file).await.expect("no err");

        let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
        for (k, v) in &files {
            if k == "SegmentMetadata.bin" {
                let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
                lfiles = sfiles;
            }
        }

        if let Ok(sfiles) = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
        {
            lfiles.extend(sfiles);
        }
    }

    let license = get_license(
        client,
        tokens,
        remote_xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return false;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return false;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        eprintln!("no content key found in license");
        return false;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let total_size = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(_, v)| v.length)
        .reduce(|old, c| old + c)
        .map_or(0, |x| x);

    let required_free_space = total_size;
    let available_free_space = match available_space(out) {
        Ok(space) => space,
        Err(err) => {
            eprintln!(
                "failed to determine available space for {}: {}",
                out.display(),
                err
            );
            return false;
        }
    };

    if available_free_space < required_free_space {
        eprintln!(
            "not enough free disk space on {}: need {} bytes, have {} bytes (files: {})",
            out.display(),
            required_free_space,
            available_free_space,
            total_size
        );
        return false;
    }

    tx.send(ProgressEvent::UpdateRemaining {
        name: "Downloading".to_owned(),
        total: total_size,
    })
    .await
    .ok();

    let remote_xvd_ref = &remote_xvd;
    let jobs: Vec<Job> = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(n, v)| Job {
            name: n.clone(),
            content: SegmentFile {
                offset: v.offset,
                length: v.length,
                data_hashs: vec![],
                keep_encrypted: v.keep_encrypted,
            },
        })
        .collect();

    // Resume progress reporting, upfront rather than trickling in: without
    // this, the aggregate percentage only catches up to bytes already on
    // disk as each file gets its turn in the `parallel` concurrency window
    // below, which for a title with hundreds/thousands of small files can
    // take a very real amount of wall-clock time even though no actual
    // network transfer is happening - all it's waiting on is scheduling,
    // not bandwidth. A single upfront synchronous stat() pass over every
    // job's target file costs milliseconds even for a huge file count, so
    // do that once here and seed the whole resumed total in one shot
    // instead of relying on the per-job catch-up event added below (which
    // still exists as a fallback/for the URL source in `run_cli_reader`'s
    // resume math, but no longer bears the up-front cost for large titles).
    if url.strip_prefix("file://").is_none() {
        let mut already_have: u64 = 0;
        for job in &jobs {
            let target_file = out.join(job.name.replace("\\", "/"));
            if let Ok(meta) = std::fs::metadata(&target_file) {
                let full_pages = meta.len() / PAGE_SIZE as u64;
                let safe_pages = full_pages.saturating_sub(1);
                already_have += (safe_pages * PAGE_SIZE as u64).min(job.content.length);
            }
        }
        if already_have > 0 {
            tx.send(ProgressEvent::Advanced {
                id: usize::MAX - 1,
                delta: already_have
            })
            .await
            .ok();
        }
    }

    stream::iter(jobs.into_iter().enumerate())
    .for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
        let tx = tx.clone();
        let client = client.clone();
        async move {
            let target_file = out.join(job.name.replace("\\", "/"));
            if let Some(folder) = target_file.parent() {
                std::fs::create_dir_all(folder).expect("ok");
            }
            let is_local_source = url.strip_prefix("file://").is_some();

            // Resume support (HTTP source only - see below): if a previous
            // attempt already wrote part of this file (retry after a
            // crash/network drop, or a fresh process picking up where an
            // earlier one left off), reuse those bytes instead of
            // re-downloading from zero. Only a same-URL/same-package resume
            // is safe - a different game version at the same path would
            // silently produce a corrupt file, so this is intentionally a
            // dumb "trust the existing size" check with no independent
            // integrity verification of the already-written bytes;
            // `download_file_http` itself still rounds down to the last
            // whole page before trusting it. Must match the page rounding
            // it applies internally - an unaligned seek here would put the
            // output position out of sync with where the page-encrypted
            // write loop actually starts writing, silently corrupting the
            // file - so this rounds down the same way.
            let resume_bytes = if is_local_source {
                0 // extract_file always reads its local source from the
                  // start, so resuming the output independently would
                  // desync write position from read position - not safe.
            } else {
                let existing_len = tokio::fs::metadata(&target_file)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);
                // Trust everything except the last whole page. A kill -9
                // (or Heroic's own abort-on-quit) can only ever leave
                // already-completed write() calls on disk - the OS finishes
                // those independently of the killed process, so a page
                // reported as written is genuinely written. A real power
                // loss / kernel panic is different: the very last in-flight
                // page can be a torn write (file length says it's there,
                // but the physical bytes are partial/garbage). Re-fetching
                // one extra page costs at most ~4KB of bandwidth and turns
                // that into a non-issue.
                let full_pages = existing_len / PAGE_SIZE as u64;
                let safe_pages = full_pages.saturating_sub(1);
                safe_pages * PAGE_SIZE as u64
            };
            let mut fout = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(resume_bytes == 0)
                .open(&target_file)
                .await
                .expect("ok");
            if resume_bytes > 0 {
                fout
                    .seek(std::io::SeekFrom::Start(resume_bytes))
                    .await
                    .expect("failed to seek to resume position");
            }
            let mut lp = resume_bytes.min(job.content.length);

            let progress = |pos, _| {
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id,
                        delta: pos - lp,
                    })
                    .is_ok()
                {
                    lp = pos;
                }
            };
            let path = job.name.to_owned();
            let shown = if path.len() > 30 {
                format!("...{}", &path[path.len() - 27..])
            } else {
                path.clone()
            };
            tx.send(ProgressEvent::Started {
                id,
                name: shown,
                total: job.content.length,
            })
            .await
            .ok();
            // Note: any already-on-disk bytes for this job were already
            // credited to the aggregate total up front (see the pre-scan
            // before this loop starts) - `lp` above already starts at
            // `resume_bytes` too, so the per-file progress closure only
            // reports genuinely new bytes from here on. Crediting it again
            // here would double-count it.

            if let Some(fpath) = url.strip_prefix("file://") {
                let mut i = File::open(&fpath).await.unwrap();
                remote_xvd_ref
                    .extract_file(&mut i, &mut fout, &job.content, *full_key, progress)
                    .await
                    .expect("msg");
                tx.send(ProgressEvent::Finished { id }).await.ok();
            } else {
                remote_xvd_ref
                    .download_file_http(
                        &client,
                        url,
                        &mut fout,
                        &job.content,
                        *full_key,
                        progress,
                        resume_bytes
                    )
                    .await
                    .expect("msg");
                tx.send(ProgressEvent::Finished { id }).await.ok();
            }
        }
    })
    .await;

    std::fs::remove_file(&final_path).ok();
    std::fs::rename(&cache_path, &final_path).expect("ok");
    true
}
