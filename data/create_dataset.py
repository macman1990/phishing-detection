import pandas as pd
import numpy as np

# Dataset بسيط للتدريب
data = {
    "url_length":        [120, 25, 95, 30, 110, 20, 88, 45, 76, 33],
    "has_ip":            [0,   0,  1,  0,  0,   0,  1,  0,  0,  0],
    "has_https":         [0,   1,  0,  1,  0,   1,  0,  1,  0,  1],
    "suspicious_words":  [3,   0,  2,  0,  4,   0,  2,  0,  3,  0],
    "spf_fail":          [1,   0,  1,  0,  1,   0,  0,  0,  1,  0],
    "dkim_fail":         [1,   0,  1,  0,  1,   0,  0,  0,  1,  0],
    "dmarc_fail":        [1,   0,  1,  0,  1,   0,  0,  0,  1,  0],
    "reply_to_mismatch": [1,   0,  0,  0,  1,   0,  1,  0,  0,  0],
    "dot_count":         [4,   2,  3,  2,  5,   2,  3,  1,  4,  2],
    "vt_score":          [85,  0,  60, 0,  90,  0,  45, 0,  70, 0],
    "label":             [1,   0,  1,  0,  1,   0,  1,  0,  1,  0],
}

df = pd.DataFrame(data)
df.to_csv("data/dataset.csv", index=False)
print(f"✅ Dataset created: {len(df)} samples")
print(df)