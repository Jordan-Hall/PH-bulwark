//! Smoke test: prove the real decode → frame-sample pipeline runs against a real
//! ffmpeg binary on this host.
//!
//! Run with the `ffmpeg` feature and (optionally) a pinned binary:
//!
//! ```text
//! export FFMPEG_BINARY=/path/to/ffmpeg
//! cargo test -p bulwark-video --features ffmpeg -- --nocapture
//! ```
//!
//! The test self-skips (early return + eprintln) when no usable ffmpeg is found,
//! so CI hosts without ffmpeg still pass. On a host *with* ffmpeg it MUST decode
//! real frames and assert their count and dimensions.
#![cfg(feature = "ffmpeg")]

use bulwark_video::ffmpeg::FfmpegDemuxer;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve ffmpeg the same way the crate does: explicit `FFMPEG_BINARY`, else
/// bare `ffmpeg` on PATH. Returns `None` if neither can actually run.
fn find_ffmpeg() -> Option<OsString> {
    let candidate: OsString = match std::env::var_os("FFMPEG_BINARY") {
        Some(p) if !p.is_empty() => p,
        _ => OsString::from("ffmpeg"),
    };
    let ok = Command::new(&candidate)
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        ok || std::env::var_os("CI").is_none(),
        "CI must provide a runnable FFmpeg binary"
    );
    ok.then_some(candidate)
}

/// Build a short synthetic clip via ffmpeg's `testsrc` lavfi source.
/// 2 seconds, 320x240, 10 fps → ~20 source frames.
///
/// `tag` keeps fixture filenames unique across the (parallel) tests in this
/// binary so they don't clobber each other's files mid-decode.
fn make_fixture(ffmpeg: &OsString, dir: &Path, tag: &str) -> PathBuf {
    let out = dir.join(format!(
        "bulwark-fixture-{}-{}.mp4",
        std::process::id(),
        tag
    ));
    let status = Command::new(ffmpeg)
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc=duration=2:size=320x240:rate=10",
            "-pix_fmt",
            "yuv420p",
        ])
        .arg(&out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn ffmpeg to build fixture");
    assert!(status.success(), "ffmpeg failed to build the test fixture");
    out
}

#[test]
fn decodes_real_frames_from_synthetic_clip() {
    let Some(ffmpeg) = find_ffmpeg() else {
        eprintln!(
            "SKIP: no runnable ffmpeg found (set FFMPEG_BINARY or put ffmpeg on PATH); \
             skipping real-decode smoke test"
        );
        return;
    };
    eprintln!("using ffmpeg binary: {}", ffmpeg.to_string_lossy());

    let tmp = std::env::temp_dir();
    let fixture = make_fixture(&ffmpeg, &tmp, "path");

    let bytes = std::fs::read(&fixture).expect("read fixture");
    let _ = std::fs::remove_file(&fixture);
    let demux = FfmpegDemuxer::with_binary(PathBuf::from(&ffmpeg));
    let decoded = bulwark_video::Demuxer::sample(
        &demux,
        &bytes,
        2.0,
        &bulwark_video::AnalysisBudget::new(5000),
    );
    assert!(
        decoded.decoded,
        "silent video must have verified audio absence"
    );
    assert_eq!(decoded.frames.len(), 4);
    assert!(decoded.audio_windows.is_empty());
    for frame in decoded.frames {
        let image = image::load_from_memory(&frame).expect("valid JPEG sample");
        assert_eq!((image.width(), image.height()), (320, 240));
    }
}

/// Also exercise the byte-oriented `Demuxer::sample` path (segment in memory),
/// which the production `VideoAnalyzer` actually calls. Reuses a small fixture
/// read back into a Vec<u8>.
#[test]
fn demuxer_trait_samples_in_memory_segment() {
    use bulwark_video::Demuxer;

    let Some(ffmpeg) = find_ffmpeg() else {
        eprintln!("SKIP: no runnable ffmpeg; skipping in-memory segment decode");
        return;
    };

    let tmp = std::env::temp_dir();
    let fixture = make_fixture(&ffmpeg, &tmp, "mem");
    let bytes = std::fs::read(&fixture).expect("read fixture bytes");
    let _ = std::fs::remove_file(&fixture);

    let demux = FfmpegDemuxer::with_binary(PathBuf::from(&ffmpeg));
    let decoded = demux.sample(&bytes, 2.0, &bulwark_video::AnalysisBudget::new(5000));

    eprintln!(
        "in-memory segment: decoded={}, frames={}",
        decoded.decoded,
        decoded.frames.len()
    );
    assert!(decoded.decoded, "segment should be marked decoded");
    assert!(
        !decoded.frames.is_empty(),
        "expected sampled frames from in-memory segment"
    );
}

struct SafeScorer;
impl bulwark_vision::Scorer for SafeScorer {
    fn score(&self, _: &[u8]) -> f32 {
        0.0
    }
    fn model_id(&self) -> &str {
        "fixture-scorer"
    }
}
struct SafeTranscriber;
impl bulwark_audio::Transcriber for SafeTranscriber {
    fn transcribe(&self, wav: &[u8]) -> Option<String> {
        assert!(wav.starts_with(b"RIFF"));
        Some("hello".into())
    }
    fn engine_id(&self) -> &str {
        "fixture-transcriber"
    }
}
#[tokio::test]
async fn real_audio_and_frame_overflow_have_distinct_coverage() {
    use bulwark_core::Analyzer;
    use bulwark_proto::v1::{analysis_request::Media, AnalysisRequest, Category, InlineMedia};
    let Some(ffmpeg) = find_ffmpeg() else {
        return;
    };
    for (tag, duration, audio, expected) in [
        ("av", 2, true, Category::Safe),
        ("overflow", 18, false, Category::Unspecified),
    ] {
        let path =
            std::env::temp_dir().join(format!("bulwark-fixture-{}-{tag}.mp4", std::process::id()));
        let mut command = Command::new(&ffmpeg);
        command
            .args(["-y", "-f", "lavfi", "-i"])
            .arg(format!("color=c=black:s=64x64:r=1:d={duration}"));
        if audio {
            command.args([
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:duration=2",
                "-shortest",
                "-c:a",
                "aac",
            ]);
        }
        let status = command
            .args(["-pix_fmt", "yuv420p"])
            .arg(&path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let demux = FfmpegDemuxer::with_binary(PathBuf::from(&ffmpeg));
        let analyzer = bulwark_video::VideoAnalyzer::with_demuxer(
            bulwark_video::VideoConfig::default(),
            demux,
        )
        .with_vision_scorer(Box::new(SafeScorer))
        .with_audio_transcriber(Box::new(SafeTranscriber));
        let verdict = analyzer
            .analyze(AnalysisRequest {
                request_id: tag.into(),
                deadline_ms: 5000,
                media: Some(Media::InlineMedia(InlineMedia {
                    data: bytes,
                    ..Default::default()
                })),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(verdict.category(), expected, "{tag}: {}", verdict.rationale);
        if !audio {
            assert_eq!(verdict.action(), bulwark_proto::v1::Action::Block);
        }
    }
}
