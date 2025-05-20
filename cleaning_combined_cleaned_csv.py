import os
import pandas as pd
import re

# Define folders
input_folder = "input"
output_folder = "dataset-cleaning"
os.makedirs(output_folder, exist_ok=True)

# Vectorized normalize_url function
def normalize_url_series(series):
    series = series.astype(str)
    series = series.str.replace(r'^https?://', '', regex=True, case=False)
    series = series.str.replace(r'^www\.', '', regex=True, case=False)
    series = series.str.rstrip('/')
    return series.str.lower()

# Load and normalize datasets
def process_dataset(filepath, url_col, label_col, source_id, label_map=None):
    df = pd.read_csv(filepath, usecols=[url_col, label_col])
    df = df.rename(columns={url_col: "url", label_col: "label"})
    if label_map:
        df["label"] = df["label"].str.strip().str.lower().map(label_map)
    df["source"] = source_id
    return df

# Load both datasets
phi_df = process_dataset(os.path.join(input_folder, "PhiUSIIL_Phishing_URL_Dataset.csv"), "URL", "label", 1)
mend_df = process_dataset(
    os.path.join(input_folder, "Mendeley April 2024.csv"),
    "url",
    "type",
    2,
    label_map={"legitimate": 0, "phishing": 1}
)

# Combine and normalize
combined_raw = pd.concat([phi_df, mend_df], ignore_index=True)
combined_raw["normalized_url"] = normalize_url_series(combined_raw["url"])

# Detect conflicting labels
label_counts = combined_raw.groupby("normalized_url")["label"].nunique()
conflicting_norm_urls = label_counts[label_counts > 1].index

conflicting_df = combined_raw[combined_raw["normalized_url"].isin(conflicting_norm_urls)]
non_conflicting_df = combined_raw[~combined_raw["normalized_url"].isin(conflicting_norm_urls)]

# Deduplicate while keeping the first occurrence
non_conflicting_df = non_conflicting_df.sort_values(by=["normalized_url", "source"])
deduplicated_df = non_conflicting_df.drop_duplicates(subset=["normalized_url"], keep="first")
duplicate_df = non_conflicting_df[~non_conflicting_df.index.isin(deduplicated_df.index)]

# Drop normalized URL for output
deduplicated_df = deduplicated_df.drop(columns=["normalized_url"])
duplicate_df = duplicate_df.drop(columns=["normalized_url"])
conflicting_df = conflicting_df.drop(columns=["normalized_url"])

# Save files
deduplicated_df.to_csv(os.path.join(output_folder, "remove_duplicate_from_combined_dataset.csv"), index=False)
duplicate_df.to_csv(os.path.join(output_folder, "duplicate_dataset_after_combining.csv"), index=False)
conflicting_df.to_csv(os.path.join(output_folder, "conflicting_label.csv"), index=False)

# Status
print("✅ Optimized deduplication complete.")
print(f"Total rows processed:        {len(combined_raw)}")
print(f"Final dataset rows:          {len(deduplicated_df)}")
print(f"Duplicates found and saved:  {len(duplicate_df)}")
print(f"Conflicting label rows:      {len(conflicting_df)}")
