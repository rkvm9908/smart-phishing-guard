import pandas as pd
import os

BASE_DATASET = "dataset/dataset.csv"
FEED_FOLDER = "data/latest_feed/"

def update_dataset():
    print("Updating dataset with latest phishing feeds...")

    # Load your existing dataset
    df_main = pd.read_csv(BASE_DATASET)

    # Loop through all CSV files inside feed folder
    for file in os.listdir(FEED_FOLDER):
        if file.endswith(".csv"):
            feed_path = os.path.join(FEED_FOLDER, file)
            print(f"Loading feed: {feed_path}")

            feed_df = pd.read_csv(feed_path)

            # Normalize according to feed patterns
            # PhishTank: column name usually 'url'
            if "url" in feed_df.columns:
                urls = feed_df["url"]
            elif "phish_url" in feed_df.columns:
                urls = feed_df["phish_url"]
            else:
                print(f"Unknown CSV format: {file}")
                continue

            # Convert into uniform structure
            new_data = pd.DataFrame({
                "url": urls,
                "label": "phishing"
            })

            # Append to main dataset
            df_main = pd.concat([df_main, new_data], ignore_index=True)

    # Remove duplicates
    df_main.drop_duplicates(subset="url", inplace=True)

    # Save updated dataset
    df_main.to_csv(BASE_DATASET, index=False)
    print("Dataset updated successfully!")

if __name__ == "__main__":
    update_dataset()
