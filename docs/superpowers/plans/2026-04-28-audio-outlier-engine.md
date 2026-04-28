# Audio Outlier Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do not create git commits unless the user explicitly requests them.

**Goal:** Build a zero-dependency Zig outlier engine that preserves the existing spectral-flux API and adds `analyzeOutlier()` for three f32 PCM clips.

**Architecture:** Keep `SpectralFluxResult` and `analyze()` unchanged. Add a separate two-pass outlier pipeline in `src/audio/fft_analyzer.zig`: first extract per-clip raw VAD/hardware/acoustic features, then run cross-clip scoring for diagnostics, MaxAD scores, common quantization grid, hardware/acoustic/final scores, and ambiguity handling.

**Tech Stack:** Zig 0.16-dev vendored compiler, Zig stdlib only, existing Cooley-Tukey FFT implementation.

---

### Task 1: Public outlier data model

**Files:**
- Modify: `src/audio/fft_analyzer.zig`

- [x] **Step 1: Add public structs after `SpectralFluxResult`**

```zig
pub const ClipInput = struct { samples: []const f32, sample_rate: u32 };
pub const SemanticLabel = enum { water, bee, steps, unknown };
pub const VADConfig = struct { announcement_skip_ms: u32 = 0, frame_ms: u32 = 10, min_active_frames: u32 = 3, snr_min: f64 = 3.0 };
pub const OutlierConfig = struct { vad: VADConfig = .{}, min_confidence: f64 = 0.15, ambiguous_score_threshold: f64 = 0.05, hardware_primary_margin: f64 = 0.20, quantization_tolerance: f64 = 0.1, low_freq_cutoff_hz: f64 = 500.0, optional_bit_depth: ?u8 = null };
pub const DecisionMode = enum { hardware_primary, weighted_fallback, ambiguous };
pub const QuantizationGridSource = enum { caller_bit_depth, runtime_common_grid };
```

- [x] **Step 2: Add feature/result structs**

```zig
pub const ActiveRegion = struct { start: usize, end: usize, noise_frame_count: u32, active_frame_count: u32, active_rms: f64, noise_floor_rms: f64, snr_estimate: f64 };
pub const HardwareSignature = struct { dc_offset: f64, dc_window_std_dev: f64, dc_bias_confidence: f64, noise_floor_rms: f64, noise_floor_confidence: f64, quantization_uniformity: f64, crest_factor: f64, rms: f64 };
pub const AcousticSignature = struct { spectral_flux: f64, spectral_rolloff: f64, zero_crossing_rate: f64, harmonic_peak_ratio: f64, spectral_centroid: f64, narrowband_stability: f64, low_frequency_transient_energy: f64 };
pub const ClipFeatures = struct { active: ActiveRegion, hardware: HardwareSignature, acoustic: AcousticSignature };
pub const OutlierScore = struct { dc_offset_score: f64, noise_floor_score: f64, quantization_uniformity_score: f64, crest_factor_score: f64, rms_energy_score: f64, spectral_flux_score: f64, spectral_rolloff_score: f64, zero_crossing_rate_score: f64, harmonic_peak_score: f64, spectral_centroid_score: f64, narrowband_stability_score: f64, low_frequency_transient_score: f64 };
pub const OutlierDiagnostics = struct { dc_delta_ratios: [CLIP_COUNT]f64, selected_quantization_grid_scale: f64, quantization_grid_source: QuantizationGridSource, score_range: f64 };
pub const OutlierAnalysisResult = struct { guess: u8, execution_time_us: u64, features: [CLIP_COUNT]ClipFeatures, outlier_scores: [CLIP_COUNT]OutlierScore, hardware_scores: [CLIP_COUNT]f64, acoustic_scores: [CLIP_COUNT]f64, final_scores: [CLIP_COUNT]f64, confidence: f64, decision_mode: DecisionMode, diagnostics: OutlierDiagnostics };
```

- [x] **Step 3: Extend `AnalysisError`**

```zig
const AnalysisError = error{ InvalidClip, InvalidSampleRate, FftTooLarge, OutputBufferTooSmall, ClipAnalysisFailed, AmbiguousSignal, NoActiveSignal };
```

- [x] **Step 4: Run compile test**

Run: `vendor/zig/zig test src/audio/fft_analyzer.zig --zig-lib-dir vendor/zig-std -lc`
Expected: existing tests compile or expose syntax issues from new declarations.

---

### Task 2: VAD and hardware feature extraction

**Files:**
- Modify: `src/audio/fft_analyzer.zig`

- [x] **Step 1: Add helpers**

```zig
fn msToSamples(ms: u32, sample_rate: u32) usize;
fn computeRangeRms(samples: []const f32, start: usize, end: usize) f64;
fn findActiveRegion(clip: []const f32, sample_rate: u32, config: VADConfig) AnalysisError!ActiveRegion;
fn computeHardwareWithoutQuantization(clip: []const f32, active: ActiveRegion) AnalysisError!HardwareSignature;
```

- [x] **Step 2: Write tests**

Add tests for `announcement_skip_ms = 0`, `announcement_skip_ms = 1000`, linear SNR, and no `dc_delta_ratio` in `HardwareSignature`.

- [x] **Step 3: Implement VAD**

Use frame energy, dynamic threshold, active frame count, active/noise RMS, and linear `snr_estimate = active_rms / noise_floor_rms`.

- [x] **Step 4: Implement DC confidence**

Use at least 5 target windows. Define `sign_consistency = dominant_sign_count / window_count`. Compute `dc_bias_confidence` from window count factor, variance factor, and sign consistency.

---

### Task 3: Common quantization grid

**Files:**
- Modify: `src/audio/fft_analyzer.zig`

- [x] **Step 1: Add helpers**

```zig
fn quantizationFractionWithin(clip: []const f32, active: ActiveRegion, grid_scale: f64, tolerance: f64) f64;
fn chooseCommonQuantizationGrid(clips: []const ClipInput, features: *[CLIP_COUNT]ClipFeatures, config: OutlierConfig) AnalysisError!struct { scale: f64, source: QuantizationGridSource };
```

- [x] **Step 2: Write tests**

Test caller bit depth uses one grid for all clips. Test runtime mode chooses `argmax sum_i fraction_within(clip_i, grid)` and does not choose per-clip grids.

- [x] **Step 3: Implement residual fraction**

Use `residual = abs(sample * grid_scale - round(sample * grid_scale))` and `fraction_within = count(residual <= tolerance) / inspected_count`.

---

### Task 4: Acoustic features

**Files:**
- Modify: `src/audio/fft_analyzer.zig`

- [x] **Step 1: Add helpers**

```zig
fn semanticLabelFromText(text: []const u8) SemanticLabel;
fn computeAcousticSignature(clip: []const f32, active: ActiveRegion, sample_rate: u32, config: OutlierConfig) AnalysisError!AcousticSignature;
```

- [x] **Step 2: Implement bounded FFT frames**

Use 1024/2048 max power-of-two frames, Hanning window, existing `fft()`, and 2-4 frames across the active region.

- [x] **Step 3: Compute metrics**

Compute spectral flux, rolloff, ZCR, harmonic peak ratio, centroid, narrowband stability, and low-frequency transient energy.

- [x] **Step 4: Write tests**

Test label parsing, bee narrowband stability, and steps low-frequency transient field presence.

---

### Task 5: Cross-clip scoring and `analyzeOutlier()`

**Files:**
- Modify: `src/audio/fft_analyzer.zig`

- [x] **Step 1: Add scoring helpers**

```zig
fn maxAdScores(values: [CLIP_COUNT]f64) [CLIP_COUNT]f64;
fn computeDcDeltaRatios(features: [CLIP_COUNT]ClipFeatures) [CLIP_COUNT]f64;
fn computeOutlierScores(features: [CLIP_COUNT]ClipFeatures) [CLIP_COUNT]OutlierScore;
fn computeHardwareScores(scores: [CLIP_COUNT]OutlierScore, features: [CLIP_COUNT]ClipFeatures) [CLIP_COUNT]f64;
fn computeAcousticScores(scores: [CLIP_COUNT]OutlierScore, label: SemanticLabel) [CLIP_COUNT]f64;
```

- [x] **Step 2: Implement score semantics**

DC MaxAD input is raw `hardware.dc_offset`. `dc_delta_ratio` is diagnostic only. Hardware score uses confidence-normalized effective weights. Acoustic score uses semantic dispatcher weights.

- [x] **Step 3: Implement public API**

```zig
pub fn analyzeOutlier(clips: []const ClipInput, label: SemanticLabel, config: OutlierConfig) !OutlierAnalysisResult;
```

- [x] **Step 4: Write tests**

Test three identical clips return `error.AmbiguousSignal`; DC outlier wins; `harmonic_peak_ratio` raw feature maps to `harmonic_peak_score`; final scores use 70/30 weighting.

---

### Task 6: Full verification

**Files:**
- Modify: `src/audio/fft_analyzer.zig`

- [ ] **Step 1: Run focused tests**

Run: `vendor/zig/zig test src/audio/fft_analyzer.zig --zig-lib-dir vendor/zig-std -lc`
Expected: all `fft_analyzer` tests pass.

- [ ] **Step 2: Run project test target**

Run: `vendor/zig/zig build test`
Expected: all project tests pass.

- [ ] **Step 3: Review acceptance criteria**

Confirm existing `analyze()` is unchanged, `SpectralFluxResult` is unchanged, zero-dependency is preserved, and no git commit was created.
