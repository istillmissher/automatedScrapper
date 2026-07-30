import json
import pandas as pd
import matplotlib.pyplot as plt
import os

# -----------------------------
# List your JSON files here
# -----------------------------
json_files = [
    r"C:\Python313\PyCharmMiscProject\JSON_dataAnalysis_script\nvdcve-2.0-2024.json",
    r"C:\Python313\PyCharmMiscProject\JSON_dataAnalysis_script\nvdcve-2.0-2023.json",
    r"C:\Python313\PyCharmMiscProject\JSON_dataAnalysis_script\nvdcve-2.0-2022.json",
    r"C:\Python313\PyCharmMiscProject\JSON_dataAnalysis_script\nvdcve-2.0-2021.json",
    # Add more files here as needed
]

# Check all listed files exist before starting
missing = [f for f in json_files if not os.path.exists(f)]
if missing:
    for f in missing:
        print(f"File not found: {f}")
    exit(1)

print(f"Processing {len(json_files)} file(s):")
for f in json_files:
    print(f"  - {os.path.basename(f)}")

records = []
skipped = 0

# Process each JSON file
for file_path in json_files:
    print(f"\nLoading: {os.path.basename(file_path)}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  Could not load file: {e}")
        continue

    if isinstance(data, list):
        vulnerabilities = data
    elif "vulnerabilities" in data:
        vulnerabilities = data["vulnerabilities"]
    else:
        print(f"  Skipping - unrecognised JSON structure in {os.path.basename(file_path)}")
        continue

    file_skipped = 0
    for v in vulnerabilities:
        try:
            cve_id = v["cve"]["id"]
            published = v["cve"]["published"]

            metrics = v["cve"].get("metrics", {})
            score = None
            severity = None

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss["baseScore"]
                severity = cvss["baseSeverity"]
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                score = cvss["baseScore"]
                severity = cvss["baseSeverity"]
            elif "cvssMetricV2" in metrics:
                entry = metrics["cvssMetricV2"][0]
                score = entry["cvssData"]["baseScore"]
                severity = entry.get("baseSeverity") or entry["cvssData"].get("baseSeverity")

            records.append({
                "CVE_ID": cve_id,
                "Published": published,
                "Score": score,
                "Severity": severity,
                "Source_File": os.path.basename(file_path)
            })
        except Exception:
            file_skipped += 1
            skipped += 1
            # Uncomment to debug individual parse failures:
            # print(f"  Skipped {v.get('cve', {}).get('id', 'unknown')}: {e}")

    print(f"  Loaded {len(vulnerabilities) - file_skipped} records ({file_skipped} skipped)")

if skipped:
    print(f"\nWarning: Skipped {skipped} records total due to parse errors.")

# Convert to DataFrame
df = pd.DataFrame(records)

# Convert date column
df["Published"] = pd.to_datetime(df["Published"], errors="coerce")

# Extract year
df["Year"] = df["Published"].dt.year

# Remove rows with missing scores or severity
df = df.dropna(subset=["Score", "Severity"])

# Normalize severity to uppercase for consistent grouping
df["Severity"] = df["Severity"].str.upper()

# -----------------------------
# Basic Analysis
# -----------------------------
print("\nTotal Vulnerabilities:", len(df))

severity_counts = df["Severity"].value_counts()
print("\nVulnerabilities by Severity:")
print(severity_counts)

year_counts = df["Year"].value_counts().sort_index()
print("\nVulnerabilities by Year:")
print(year_counts)

# -----------------------------
# Charts
# -----------------------------
output_dir = os.path.dirname(os.path.abspath(__file__))

# Pie chart for severity distribution
plt.figure(figsize=(6, 6))
severity_counts.plot(
    kind="pie",
    autopct="%1.1f%%",
    startangle=90
)
plt.title("Vulnerability Severity Distribution")
plt.ylabel("")
plt.tight_layout()
pie_path = os.path.join(output_dir, "severity_distribution.png")
plt.savefig(pie_path, dpi=150)
plt.close()
print(f"\nSeverity pie chart saved to: {pie_path}")

# Bar chart for vulnerabilities per year
plt.figure(figsize=(8, 5))
year_counts.plot(kind="bar")
plt.title("Vulnerabilities by Year")
plt.xlabel("Year")
plt.ylabel("Number of Vulnerabilities")
plt.xticks(rotation=45)
plt.tight_layout()
bar_path = os.path.join(output_dir, "vulnerabilities_by_year.png")
plt.savefig(bar_path, dpi=150)
plt.close()
print(f"Year bar chart saved to: {bar_path}")

# -----------------------------
# Export Processed Dataset
# -----------------------------
output_file = os.path.join(output_dir, "processed_vulnerabilities.csv")
df.to_csv(output_file, index=False)
print(f"\nClean dataset exported to: {output_file}")