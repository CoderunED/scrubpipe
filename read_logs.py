import json
with open("sample_logs.json","r") as f:
    logs = json.load(f)

print(f"Loaded {len(logs)} log events")
print("First event email:", logs[0]["user_email"])
logs[0]["user_email"]="REDACTED"
logs[1]["user_email"]="REDACTED"
logs[0]["src_ip"]="REDACTED"
logs[1]["src_ip"]="REDACTED"
with open("output_logs.json", "w") as f:
    json.dump(logs,f,indent=2)
print("Wrote output_logs.json")