import os
import pandas as pd
import re
import logging

# Setup logging
# Corrected: Use standard single quotes for the format string
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# --- Configuration ---
INPUT_FOLDER = "input"
OUTPUT_FOLDER = "cleaned_data" # Use a new folder for clarity
FILE1_PATH = os.path.join(INPUT_FOLDER, "PhiUSIIL_Phishing_URL_Dataset.csv")
FILE2_PATH = os.path.join(INPUT_FOLDER, "Mendeley April 2024.csv")

FILE1_URL_COL = "URL"
FILE1_LABEL_COL = "label"
FILE1_SOURCE_ID = 1

FILE2_URL_COL = "url"
FILE2_LABEL_COL = "type"
FILE2_SOURCE_ID = 2
FILE2_LABEL_MAP = {"legitimate": 0, "phishing": 1}

OUTPUT_FILE1 = os.path.join(OUTPUT_FOLDER, "PhiUSIIL_cleaned_v2.csv")
OUTPUT_FILE2 = os.path.join(OUTPUT_FOLDER, "Mendeley_cleaned_v2.csv")
OUTPUT_CONFLICTS = os.path.join(OUTPUT_FOLDER, "conflicts_v2.csv")
# --- End Configuration ---

def normalize_url(url):
    """Normalize a single URL string."""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    url = re.sub(r"^www\.", "", url, flags=re.IGNORECASE)
    url = url.rstrip("/")
    return url.lower()

def process_and_clean_datasets_v2(file1_path, file2_path):
    """Loads, cleans, and deduplicates two datasets, removing all conflicts first."""
    try:
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)

        # Load datasets with explicit UTF-8 encoding
        log.info(f"Loading dataset 1: {file1_path}")
        try:
            # Corrected: Use standard double quotes for encoding/errors
            df1 = pd.read_csv(file1_path, usecols=[FILE1_URL_COL, FILE1_LABEL_COL], encoding="utf-8")
        except UnicodeDecodeError:
            log.warning(f"UTF-8 decoding failed for {file1_path}. Trying with errors='ignore'.")
            df1 = pd.read_csv(file1_path, usecols=[FILE1_URL_COL, FILE1_LABEL_COL], encoding="utf-8", errors="ignore")
            
        df1 = df1.rename(columns={FILE1_URL_COL: "url", FILE1_LABEL_COL: "label"})
        df1["source"] = FILE1_SOURCE_ID
        # Corrected: Use standard single quotes for errors/astype
        df1["label"] = pd.to_numeric(df1["label"], errors='coerce').astype('Int64')
        df1.dropna(subset=["url", "label"], inplace=True)
        log.info(f"Loaded {len(df1)} rows from dataset 1.")

        log.info(f"Loading dataset 2: {file2_path}")
        try:
            # Corrected: Use standard double quotes for encoding/errors
            df2 = pd.read_csv(file2_path, usecols=[FILE2_URL_COL, FILE2_LABEL_COL], encoding="utf-8")
        except UnicodeDecodeError:
            log.warning(f"UTF-8 decoding failed for {file2_path}. Trying with errors='ignore'.")
            df2 = pd.read_csv(file2_path, usecols=[FILE2_URL_COL, FILE2_LABEL_COL], encoding="utf-8", errors="ignore")
            
        df2 = df2.rename(columns={FILE2_URL_COL: "url", FILE2_LABEL_COL: "label"})
        df2["label"] = df2["label"].str.strip().str.lower().map(FILE2_LABEL_MAP)
        df2["source"] = FILE2_SOURCE_ID
        # Corrected: Use standard single quotes for errors/astype
        df2["label"] = pd.to_numeric(df2["label"], errors='coerce').astype('Int64')
        df2.dropna(subset=["url", "label"], inplace=True)
        log.info(f"Loaded {len(df2)} rows from dataset 2.")

        # Normalize URLs
        log.info("Normalizing URLs...")
        df1["normalized_url"] = df1["url"].apply(normalize_url)
        df2["normalized_url"] = df2["url"].apply(normalize_url)

        # Remove rows with empty normalized URLs
        df1 = df1[df1["normalized_url"] != ""]
        df2 = df2[df2["normalized_url"] != ""]
        log.info(f"Dataset 1 size after empty norm URL removal: {len(df1)}")
        log.info(f"Dataset 2 size after empty norm URL removal: {len(df2)}")

        # --- Identify ALL conflicts across the combined raw data --- 
        log.info("Identifying all label conflicts across combined data...")
        combined_raw = pd.concat([
            df1[["normalized_url", "label"]],
            df2[["normalized_url", "label"]]
        ], ignore_index=True)
        
        # Find URLs with more than one unique label associated with them ANYWHERE
        label_consistency = combined_raw.groupby("normalized_url")["label"].nunique()
        conflicting_urls_set = set(label_consistency[label_consistency > 1].index)
        log.info(f"Found {len(conflicting_urls_set)} normalized URLs with conflicting labels.")

        # --- Save Conflicts --- 
        log.info("Separating and saving conflicting rows...")
        conflicts1_df = df1[df1["normalized_url"].isin(conflicting_urls_set)].copy()
        conflicts2_df = df2[df2["normalized_url"].isin(conflicting_urls_set)].copy()
        all_conflicts_df = pd.concat([conflicts1_df, conflicts2_df], ignore_index=True)
        all_conflicts_df.sort_values(by=["normalized_url", "source"], inplace=True)
        
        if not all_conflicts_df.empty:
             all_conflicts_df.drop(columns=["normalized_url"], inplace=True)
             # Save conflicts with UTF-8 encoding
             # Corrected: Use standard double quotes for encoding
             all_conflicts_df.to_csv(OUTPUT_CONFLICTS, index=False, encoding="utf-8")
             log.info(f"Saved {len(all_conflicts_df)} conflicting rows to: {OUTPUT_CONFLICTS}")
        else:
             log.info("No conflicting rows found to save.")

        # --- Filter out conflicts from original dataframes --- 
        log.info("Removing conflicting URLs from datasets...")
        df1_filtered = df1[~df1["normalized_url"].isin(conflicting_urls_set)].copy()
        df2_filtered = df2[~df2["normalized_url"].isin(conflicting_urls_set)].copy()
        log.info(f"Dataset 1 size after conflict removal: {len(df1_filtered)}")
        log.info(f"Dataset 2 size after conflict removal: {len(df2_filtered)}")

        # --- Intra-file deduplication on filtered data (keep first) ---
        log.info("Performing intra-file deduplication on non-conflicting data...")
        df1_dedup = df1_filtered.drop_duplicates(subset=["normalized_url"], keep="first").copy()
        df2_dedup = df2_filtered.drop_duplicates(subset=["normalized_url"], keep="first").copy()
        log.info(f"Dataset 1 size after intra-dedup: {len(df1_dedup)}")
        log.info(f"Dataset 2 size after intra-dedup: {len(df2_dedup)}")

        # --- Identify common URLs between the clean, deduplicated sets --- 
        log.info("Identifying common URLs between cleaned datasets...")
        common_clean_urls = set(df1_dedup["normalized_url"]) & set(df2_dedup["normalized_url"])
        log.info(f"Found {len(common_clean_urls)} common URLs between final cleaned datasets.")
        # These common URLs must have consistent labels because conflicts were already removed.

        # --- Final Filtering based on rules ---
        # Keep all of df1_dedup (it has priority for common URLs)
        df1_final = df1_dedup
        # Remove common URLs from df2_dedup
        df2_final = df2_dedup[~df2_dedup["normalized_url"].isin(common_clean_urls)].copy()
        log.info(f"Final Dataset 1 size: {len(df1_final)}")
        log.info(f"Final Dataset 2 size (after removing common): {len(df2_final)}")

        # --- Save final files ---
        log.info("Saving final datasets...")
        df1_final.drop(columns=["normalized_url"], inplace=True)
        df2_final.drop(columns=["normalized_url"], inplace=True)

        # Save final files with UTF-8 encoding
        # Corrected: Use standard double quotes for encoding
        df1_final.to_csv(OUTPUT_FILE1, index=False, encoding="utf-8")
        df2_final.to_csv(OUTPUT_FILE2, index=False, encoding="utf-8")

        log.info(f"Cleaned dataset 1 saved to: {OUTPUT_FILE1} ({len(df1_final)} rows)")
        log.info(f"Cleaned dataset 2 saved to: {OUTPUT_FILE2} ({len(df2_final)} rows)")

        return True

    except FileNotFoundError as e:
        log.error(f"Error: Input file not found - {e}")
        return False
    except KeyError as e:
        log.error(f"Error: Column not found in input file - {e}. Check column names.")
        return False
    except Exception as e:
        log.exception(f"An unexpected error occurred during processing: {e}")
        return False

if __name__ == "__main__":
    # Corrected: Removed placeholder comments and print statement, fixed logging setup
    # Corrected: Use standard single quotes for the format string
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    log = logging.getLogger(__name__)
    
    log.info("Starting dataset cleaning process (v2 - conflicts first, UTF-8 handling)...")
    success = process_and_clean_datasets_v2(FILE1_PATH, FILE2_PATH)
    if success:
        log.info("Dataset cleaning process completed successfully.")
    else:
        log.error("Dataset cleaning process failed.")

