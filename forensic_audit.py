import os
import numpy as np
import glob
from scipy.signal import correlate, find_peaks
import warnings
warnings.filterwarnings('ignore')

def extract_segments(audio, sr=44100):
    win_len = int(sr * 0.05)
    squared = audio**2
    window = np.ones(win_len)/win_len
    envelope = np.convolve(squared, window, mode='same')
    envelope_db = 10 * np.log10(envelope + 1e-10)
    
    threshold = -35 # dB
    active = envelope_db > threshold
    
    changes = np.diff(active.astype(int))
    starts = np.where(changes == 1)[0]
    ends = np.where(changes == -1)[0]
    
    if len(starts) == 0 or len(ends) == 0: return []
    if ends[0] < starts[0]: ends = ends[1:]
    if len(starts) > len(ends): starts = starts[:-1]
        
    segments = []
    for s, e in zip(starts, ends):
        if (e - s) > sr * 0.2:
            segments.append((s, e))
    return segments

def get_outlier_delta(vals):
    m = np.mean(vals)
    d = np.abs(np.array(vals) - m) / (np.abs(m) + 1e-10) * 100
    idx = np.argmax(d)
    return d[idx], idx + 1 

def analyze_file(filepath):
    audio = np.fromfile(filepath, dtype=np.float32)
    sr = 44100
    segments = extract_segments(audio, sr)
    
    if len(segments) < 6:
        return f"### Dosya: `{os.path.basename(filepath)}`\nSonuçsuz Segment Sayısı ({len(segments)}). Ses zayıf veya ayıklanamadı.\n"
        
    segment_lengths = [(e-s) for s,e in segments]
    sorted_idx = np.argsort(segment_lengths)[::-1]
    clip_idx = sorted(sorted_idx[:3])
    
    clip_idx = sorted(clip_idx)
    
    if len(clip_idx) != 3:
        return f"### Dosya: `{os.path.basename(filepath)}`\nSonuçsuz segmentler.\n"
        
    clips = [audio[segments[i][0]:segments[i][1]] for i in clip_idx]
    
    stats = {}
    metrics = ['RMS Enerjisi (dBFS)', 'Zirve Enerjisi (dBFS)', 'Gürültü Tabanı (dB)', 'Spektral Merkez (Hz)', 
               'Spektral Yuvarlanma %85 (Hz)', 'Krest Faktörü', 'Sıfır Geçiş Oranı (ZCR)', 'Yükselme Süresi (ms)', 'Periyodiklik (Hz)', 'DC Sapması']
    
    for m in metrics:
        stats[m] = []
        
    for clip in clips:
        rms = np.sqrt(np.mean(clip**2))
        rms_db = 20 * np.log10(rms + 1e-10)
        peak_val = np.max(np.abs(clip))
        peak_db = 20 * np.log10(peak_val + 1e-10)
        crest_factor = peak_val / (rms + 1e-10)
        
        fft_out = np.abs(np.fft.rfft(clip, n=4096))
        freqs = np.fft.rfftfreq(4096, d=1/sr)
        
        sorted_fft = np.sort(fft_out)
        noise_floor = 20 * np.log10(np.mean(sorted_fft[:int(len(sorted_fft)*0.05)]) + 1e-10)
        
        spectral_centroid = np.sum(freqs * fft_out) / (np.sum(fft_out) + 1e-10)
        
        cum_sum = np.cumsum(fft_out)
        rolloff_idx = np.where(cum_sum >= 0.85 * cum_sum[-1])[0][0]
        spectral_rolloff = freqs[rolloff_idx]
        
        zcr = np.mean(np.abs(np.diff(np.sign(clip)))) / 2 * sr
        
        dc_offset = np.mean(clip)
        
        win = int(sr * 0.005) 
        env = np.convolve(np.abs(clip), np.ones(win)/win, mode='same')
        diff_env = np.diff(env)
        max_grad = np.max(diff_env)
        rise_time = 1.0 / (max_grad + 1e-10) * 1000 if max_grad > 0 else 0
        
        autocorr = correlate(clip[:sr*1], clip[:sr*1], mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        peaks, _ = find_peaks(autocorr, distance=sr//50)
        if len(peaks) > 1:
            periodicity = sr / peaks[1]
        else:
            periodicity = 0.0
            
        stats['RMS Enerjisi (dBFS)'].append(rms_db)
        stats['Zirve Enerjisi (dBFS)'].append(peak_db)
        stats['Gürültü Tabanı (dB)'].append(noise_floor)
        stats['Spektral Merkez (Hz)'].append(spectral_centroid)
        stats['Spektral Yuvarlanma %85 (Hz)'].append(spectral_rolloff)
        stats['Krest Faktörü'].append(crest_factor)
        stats['Sıfır Geçiş Oranı (ZCR)'].append(zcr)
        stats['Yükselme Süresi (ms)'].append(rise_time)
        stats['Periyodiklik (Hz)'].append(periodicity)
        stats['DC Sapması'].append(dc_offset)

    noise_len = min(int(sr * 0.1), len(clips[0]), len(clips[1]), len(clips[2]))
    n1 = clips[0][:noise_len]
    n2 = clips[1][:noise_len]
    n3 = clips[2][:noise_len]
    
    def norm(x):
        return (x - np.mean(x)) / (np.std(x) + 1e-10)
        
    xcorr_12 = np.max(np.correlate(norm(n1), norm(n2), mode='valid')) / noise_len
    xcorr_13 = np.max(np.correlate(norm(n1), norm(n3), mode='valid')) / noise_len
    xcorr_23 = np.max(np.correlate(norm(n2), norm(n3), mode='valid')) / noise_len
    
    noise_msg = "DİJİTAL OLARAK BİREBİR KOPYALANMIŞ" if (xcorr_12 > 0.9 or xcorr_13 > 0.9 or xcorr_23 > 0.9) else "BENZERSİZ STOKASTİK (Farklı Kayıt)"
    
    res = f"### Dosya: `{os.path.basename(filepath)}`\n"
    res += f"**Arka Plan Gürültü Profili:** {noise_msg}\n"
    res += f"**Çapraz Korelasyon (İlk 100ms):** 1-2: {xcorr_12:.3f} | 1-3: {xcorr_13:.3f} | 2-3: {xcorr_23:.3f}\n\n"
    res += f"| Metrik | Seçenek 1 | Seçenek 2 | Seçenek 3 | Sapkınlık Deltası (Aykırı Değer) |\n"
    res += f"| :--- | :--- | :--- | :--- | :--- |\n"
    
    for m in metrics:
        vals = stats[m]
        delta, out_idx = get_outlier_delta(vals)
        outlier_str = f"**%{(delta):.1f} (Seçenek {out_idx})**" if delta > 25.0 else f"%{delta:.1f}"
        
        if 'dB' in m or 'dBFS' in m:
            row = f"| {m} | {vals[0]:.2f} | {vals[1]:.2f} | {vals[2]:.2f} | {outlier_str} |"
        elif 'DC' in m:
            row = f"| {m} | {vals[0]:.3e} | {vals[1]:.3e} | {vals[2]:.3e} | {outlier_str} |"
        elif 'Yükselme' in m:
            row = f"| {m} | {vals[0]:.2e} | {vals[1]:.2e} | {vals[2]:.2e} | {outlier_str} |"
        else:
            row = f"| {m} | {vals[0]:.2f} | {vals[1]:.2f} | {vals[2]:.2f} | {outlier_str} |"
        res += row + "\n"
        
    return res + "\n"

if __name__ == "__main__":
    files = sorted(glob.glob('/home/void0x14/Documents/ihsan-agama-verilen-destek/doggystyle/tmp/*.f32'))
    output = []
    output.append("# ADLİ SES ANALİZ RAPORU (TAM LİSTE)\n")
    for f in files: 
        output.append(analyze_file(f))
    
    with open('/home/void0x14/Documents/ihsan-agama-verilen-destek/doggystyle/tmp/forensic_report.md', 'w') as f:
        f.write("\n".join(output))
    print(f"Rapor yazildi. Toplam dosya: {len(files)}")
