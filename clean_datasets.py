import os
import pandas as pd
import re

# Define folders
input_folder = "input"
output_folder = "dataset-cleaning"
os.makedirs(output_folder, exist_ok=True)

# Normalize URLs (for matching purposes only)
def normalize_url(url):
    url = str(url)
    url = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
    url = re.sub(r'^www\.', '', url, flags=re.IGNORECASE)
    url = url.rstrip('/')
    return url.lower()

# Process individual dataset
def process_dataset(filepath, url_col, label_col, source_id, label_map=None):
    df = pd.read_csv(filepath, usecols=[url_col, label_col])
    df = df.rename(columns={url_col: "url", label_col: "label"})

    if label_map:
        df["label"] = df["label"].str.strip().str.lower().map(label_map)

    df["normalized_url"] = df["url"].apply(normalize_url)
    df["source"] = source_id

    return df

# 1. Process PhiUSIIL
phi_file = os.path.join(input_folder, "PhiUSIIL_Phishing_URL_Dataset.csv")
phi_df = process_dataset(phi_file, "URL", "label", 1)

# 2. Process Mendeley
mend_file = os.path.join(input_folder, "Mendeley April 2024.csv")
mend_df = process_dataset(
    mend_file, "url", "type", 2, label_map={"legitimate": 0, "phishing": 1}
)

# 3. Combine raw data
combined_raw = pd.concat([phi_df, mend_df], ignore_index=True)

# 4. Group by normalized URL to detect duplicates
grouped = combined_raw.groupby("normalized_url")

final_rows = []
duplicate_rows = []
conflicting_rows = []

seen = {}

for norm_url, group in grouped:
    labels = group["label"].unique()
    if len(labels) > 1:
        # Conflicting labels
        group["conflict_info"] = f"Conflicting labels found: {labels.tolist()}"
        conflicting_rows.append(group)
    else:
        # Same label
        first = group.iloc[0]
        final_rows.append(first)
        if len(group) > 1:
            duplicate_rows.append(group.iloc[1:])

# 5. Convert result sets to DataFrames
final_df = pd.DataFrame(final_rows).drop(columns=["normalized_url"])
duplicate_df = pd.concat(duplicate_rows).drop(columns=["normalized_url"]) if duplicate_rows else pd.DataFrame()
conflicting_df = pd.concat(conflicting_rows).drop(columns=["normalized_url"]) if conflicting_rows else pd.DataFrame()

# 6. Save outputs
final_path = os.path.join(output_folder, "remove_duplicate_from_combined_dataset.csv")
duplicate_path = os.path.join(output_folder, "duplicate_dataset_after_combining.csv")
conflict_path = os.path.join(output_folder, "conflicting_label.csv")

final_df.to_csv(final_path, index=False)
if not duplicate_df.empty:
    duplicate_df.to_csv(duplicate_path, index=False)
if not conflicting_df.empty:
    conflicting_df.to_csv(conflict_path, index=False)

# 7. Print status
print("De-duplication and conflict resolution complete.")
print(f"Total rows processed:        {len(combined_raw)}")
print(f"Final dataset rows:          {len(final_df)}")
print(f"Duplicates found and saved:  {len(duplicate_df)}")
print(f"Conflicting label rows:      {len(conflicting_df)}")
