import kagglehub
import os
import zipfile

# Authenticate using your token (from "Generate New Token" button)
os.environ['KAGGLE_API_TOKEN'] = "KGAT_c1a95299c3af1b1ccac4350bfa2d57bf"  # 👈 REPLACE WITH YOUR TOKEN

# Download Deepfake dataset
print("Downloading Deepfake dataset...")
deepfake_path = kagglehub.dataset_download("xhlulu/140k-real-and-fake-faces")
print(f"Deepfake dataset downloaded to: {deepfake_path}")

# Download Phishing dataset
print("Downloading Phishing dataset...")
phishing_path = kagglehub.dataset_download("shashwatwork/phishing-dataset-for-machine-learning")
print(f"Phishing dataset downloaded to: {phishing_path}")

# Move and unzip to your project folders
os.makedirs("data/deepfake", exist_ok=True)
os.makedirs("data/phishing", exist_ok=True)

# For deepfake – it's already extracted by kagglehub
# Just copy contents
import shutil
for item in os.listdir(deepfake_path):
    s = os.path.join(deepfake_path, item)
    d = os.path.join("data/deepfake", item)
    if os.path.isdir(s):
        shutil.copytree(s, d, dirs_exist_ok=True)
    else:
        shutil.copy2(s, d)

# For phishing – find the CSV file
for root, dirs, files in os.walk(phishing_path):
    for file in files:
        if file.endswith(".csv"):
            shutil.copy2(os.path.join(root, file), "data/phishing/phishing_data.csv")
            break

print("✅ Datasets ready in 'data/' folder!")