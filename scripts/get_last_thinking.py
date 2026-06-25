import json

log_path = "/home/ems/.gemini/antigravity-ide/brain/7b1a3225-f45d-44c4-8744-5f29c1b64cf6/.system_generated/logs/transcript.jsonl"
with open(log_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")
print("--- Last 15 Steps ---")
for line in lines[-15:]:
    data = json.loads(line)
    step = data.get("step_index")
    source = data.get("source")
    typ = data.get("type")
    print(f"Step {step} | Source: {source} | Type: {typ}")
    thinking = data.get("thinking")
    if thinking:
        print(f"  Thinking: {thinking}")
    content = data.get("content")
    if content and not thinking:
        print(f"  Content (truncated 200): {content[:200]}")
    tool_calls = data.get("tool_calls")
    if tool_calls:
        print(f"  Tool Calls: {tool_calls}")
    print()
