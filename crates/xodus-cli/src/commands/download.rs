use std::process::ExitCode;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use tokio::io::AsyncWriteExt;
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::package::{get_content_id, get_packages};

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    market: Option<String>,
    dry_run: bool,
) -> ExitCode {
    let content_id_task = get_content_id(client, product, market).await;
    let Ok(content_id) = content_id_task else {
        let Err(err) = content_id_task else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
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

    let Ok(files) = MultiSelect::new("Select files to download", package.package_files)
        .with_page_size(30)
        .with_validator(|input: &[inquire::list_option::ListOption<&PackageFile>]| {
            if !input.is_empty() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "At least one item has to be selected".into(),
                ))
            }
        })
        .prompt()
    else {
        log::error!("Selection failed");
        return ExitCode::FAILURE;
    };
    println!();
    for file in files {
        let Some(cdn_root) = file.cdn_root_paths.first() else {
            eprintln!(
                "'{}' has no CDN root paths to download from",
                file.file_name
            );
            return ExitCode::FAILURE;
        };
        let url = format!("{cdn_root}{}", file.relative_url);
        if dry_run {
            println!("{}", url);
            return ExitCode::SUCCESS;
        }

        let progress_bar = ProgressBar::new(file.file_size as u64).with_style(
            ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})").unwrap()
            .progress_chars("#>-")
        );

        let res = match client
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
        {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Failed to request '{}': {err}", file.file_name);
                return ExitCode::FAILURE;
            }
        };
        let mut out_file = match tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file.file_name)
            .await
        {
            Ok(out_file) => out_file,
            Err(err) => {
                eprintln!("Could not open '{}' for writing: {err}", file.file_name);
                return ExitCode::FAILURE;
            }
        };
        let mut stream = res.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chk = match chunk {
                Ok(chk) => chk,
                Err(err) => {
                    eprintln!("Download of '{}' interrupted: {err}", file.file_name);
                    drop(out_file);
                    let _ = tokio::fs::remove_file(&file.file_name).await;
                    return ExitCode::FAILURE;
                }
            };
            if let Err(err) = out_file.write_all(&chk).await {
                eprintln!("Failed to write '{}' to disk: {err}", file.file_name);
                drop(out_file);
                let _ = tokio::fs::remove_file(&file.file_name).await;
                return ExitCode::FAILURE;
            }
            progress_bar.inc(chk.len() as u64);
        }

        progress_bar.finish();
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}
