import json

INPUT_FILE = "stealth.json"
OUTPUT_FILE = "stealth_prereqs.ps1"

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for technique in data.keys():
        f.write(f"Invoke-AtomicTest {technique} -GetPrereqs\n")

print(f"Đã tạo {OUTPUT_FILE} với {len(data)} lệnh.")
