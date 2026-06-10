//! Model-output postprocessing: raw classifier head → flag probability and the
//! severity ladder. ALWAYS compiled (no `ort` dependency) so (a) the math is
//! unit-tested on the default build with no model runtime present, and (b)
//! `bulwark-infer`'s local first-pass seam maps scores → verdicts with exactly
//! the same conventions as this crate's live `onnx` scorer — the on-device and
//! server paths cannot drift.

use bulwark_proto::v1::Severity;

/// Map raw model output logits/probabilities to an NSFW probability.
///
/// * len 1            → `sigmoid(x[0])`.
/// * len 2+           → `softmax`, take the highest-indexed (nsfw) class.
/// * already in [0,1] → if a single value is already a probability we still
///   pass it through sigmoid/softmax above; callers wanting raw probabilities
///   should export a sigmoid head.
pub fn nsfw_probability(logits: &[f32]) -> f32 {
    match logits.len() {
        0 => 0.0,
        1 => sigmoid(logits[0]),
        _ => {
            let probs = softmax(logits);
            // Convention: last class is "nsfw" (Falconsai: 0=normal, 1=nsfw).
            *probs.last().unwrap_or(&0.0)
        }
    }
    .clamp(0.0, 1.0)
}

/// The severity ladder shared by the image verdict builders (this crate's
/// analyzer and bulwark-infer's local first-pass seam).
pub fn severity_for(score: f32) -> Severity {
    if score >= 0.9 {
        Severity::High
    } else if score >= 0.7 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

fn softmax(xs: &[f32]) -> Vec<f32> {
    let max = xs.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = xs.iter().map(|&x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum == 0.0 {
        return vec![0.0; xs.len()];
    }
    exps.into_iter().map(|e| e / sum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigmoid_and_softmax_math() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid(20.0) > 0.99);
        assert!(sigmoid(-20.0) < 0.01);

        let p = softmax(&[1.0, 1.0]);
        assert!((p[0] - 0.5).abs() < 1e-6 && (p[1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn postprocess_heads() {
        // 1-logit sigmoid head.
        assert!((nsfw_probability(&[0.0]) - 0.5).abs() < 1e-6);
        // 2-class softmax head; class 1 ("nsfw") dominant.
        let p = nsfw_probability(&[0.0, 10.0]);
        assert!(p > 0.99, "nsfw class dominant → ~1.0, got {p}");
        let p = nsfw_probability(&[10.0, 0.0]);
        assert!(p < 0.01, "normal class dominant → ~0.0, got {p}");
        assert_eq!(nsfw_probability(&[]), 0.0);
    }

    #[test]
    fn severity_ladder() {
        assert_eq!(severity_for(0.95), Severity::High);
        assert_eq!(severity_for(0.75), Severity::Medium);
        assert_eq!(severity_for(0.5), Severity::Low);
    }
}
