import requests
import json
from dotenv import load_dotenv
import os

load_dotenv()

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
conversation_context = []


def parse_response(content):
    import re
    text_no_headers = re.sub(r"### \*\*.*?\*\*", "", content)
    text_no_tables = re.sub(r"\|.*?\|", "", text_no_headers)
    text_clean = re.sub(r"\n{2,}", "\n\n", text_no_tables).strip()
    print("Parsed DeepSeek Response:\n")
    return text_clean

def call_deepseek(conversation_context):
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "model": "deepseek-chat",
        "messages": conversation_context,
        "temperature": 0.7,
        "max_tokens": 1024,
    }
    
    try:
        response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload)
        response.raise_for_status() 
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}



if __name__ == "__main__":
    predicted_label = "beacon"
    malware_json = {
  "sample_id": "85b120a7-0fb9-42c1-a2c8-8857382edd65",
  "label": "beacon",
  "target_proc": {
    "name": "python",
    "pid": 9960,
    "exe": "",
    "ppid": None,
    "signed": False
  },
  "timeline": [
    {
      "t": 1.903,
      "type": "file_modify",
      "path": "C:\\sandbox\\beacon\\stage.bin"
    },
    {
      "t": 1.9009132385253906,
      "type": "dns_query",
      "domain": "cdn-updates.example"
    },
    {
      "t": 1.9009218215942383,
      "type": "dns_query",
      "domain": "telemetry.service"
    },
    {
      "t": 1.9009246826171875,
      "type": "dns_query",
      "domain": "analytics.host"
    },
    {
      "t": 1.904,
      "type": "file_modify",
      "path": "C:\\sandbox\\beacon\\stage.bin"
    }
  ],
  "rollups": {
    "file_create": 0,
    "file_delete": 0,
    "file_modify": 2,
    "folder_create": 0,
    "folder_delete": 0,
    "reg_set": 0,
    "reg_delete": 0,
    "dns_query": 6,
    "net_connect": 0,
    "proc_spawn": 0,
    "cpu_max": 15.2,
    "duration_s": 2.21,
    "unique_exts": 1
  }
}
    # Combine multiple prompts into one
    user_prompt = f"""
A malware sample has been detected with label: {predicted_label}.
Behavior JSON:

{json.dumps(malware_json, indent=2)}
we are doing behavioural analysis of malware and we are detecting ans classifying a malware.
 the json collects the log files and indicates the sequence of actions.
 Tell me whether those actions represent the behaviour of malware and what is the probability that it is a malware

Please provide:
1. A human-readable explanation of this malware's behavior.
2. Relevant MITRE ATT&CK techniques and tactics.
3. Recommended mitigation strategies and monitoring actions.
4. Any other potential insights or observations about this malware.
"""

    api_response = call_deepseek([{"role": "user", "content": user_prompt}])   
    
    print("DeepSeek API Response:")
    print(json.dumps(api_response, indent=2))
    content = api_response['choices'][0]['message']['content']
    print(parse_response(content))
    print("*************************************************")    
    conversation_context.append({"role": "assistant", "content": content})
    conversation_context.append({"role": "user", "content": "can you explain why the DNS queries are suspicious ?"})

    api_response = call_deepseek(conversation_context)   
    print(json.dumps(api_response, indent=2))

    print("DeepSeek API Response:")
    # print(json.dumps(api_response, indent=2))
    content1 = api_response['choices'][0]['message']['content']
    print(parse_response(content1))



    