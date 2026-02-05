import os
import re
import json
import random
import requests
import time
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel

# ==========================================
# 1. CONFIGURATION
# ==========================================
APP_NAME = "Agentic Honeypot - Final"
# Your secret key. Keep this safe.
API_KEY = os.getenv("API_KEY", "SECRET_123") 
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# LLM Config (Optional - Code works even if these are empty)
LLM_API_KEY = os.getenv("LLM_API_KEY", "") 
LLM_URL = "https://api.openai.com/v1/chat/completions"

# Redis Config (Optional - Falls back to memory if empty)
REDIS_URL = os.getenv("REDIS_URL", "")

# ==========================================
# 2. STATE MANAGEMENT (Crash-Proof)
# ==========================================
MEMORY_DB = {}

def get_session(session_id: str):
    """Try Redis first, fallback to RAM. Ensures no 500 errors."""
    if REDIS_URL:
        try:
            import redis
            r = redis.from_url(REDIS_URL, decode_responses=True)
            data = r.get(session_id)
            return json.loads(data) if data else None
        except:
            pass # Fail silently to memory
    return MEMORY_DB.get(session_id)

def save_session(session_id: str, data: Dict):
    """Save state so we remember the scammer's previous data."""
    if REDIS_URL:
        try:
            import redis
            r = redis.from_url(REDIS_URL, decode_responses=True)
            r.setex(session_id, 21600, json.dumps(data)) # 6 hours TTL
            return
        except:
            pass
    MEMORY_DB[session_id] = data

def init_session(session_id: str):
    return {
        "sessionId": session_id,
        "turns": 0,
        "scamDetected": False,
        "callbackSent": False,
        "noNewIntelTurns": 0,
        "intel": {
            "upiIds": [], "bankAccounts": [], "phoneNumbers": [],
            "phishingLinks": [], "suspiciousKeywords": []
        }
    }

# ==========================================
# 3. INTELLIGENCE ENGINE (The Point Scorer)
# ==========================================
def extract_intel(text: str) -> Dict[str, List[str]]:
    # Normalize text to catch "hidden" info
    text_clean = re.sub(r'\s+', ' ', text).strip()
    
    # 1. UPI (Greedy regex to catch any handle)
    upis = list(set(re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", text_clean)))
    
    # 2. Links (HTTP/HTTPS/WWW)
    links = list(set(re.findall(r"https?://\S+|www\.\S+", text_clean)))
    
    # 3. Phones (Advanced "De-cloaking")
    # Catches: +91 98765, 9 8 7 6 5, 098765
    raw_nums = re.findall(r"(?:\+?91|0)?[-\s]?(?:\d[-\s]?){10}", text_clean)
    phones = set()
    for n in raw_nums:
        clean_n = re.sub(r"\D", "", n)
        # Verify length to avoid timestamps (timestamps usually start with 1 and are 10 digits, 
        # but Indian mobiles start with 6-9. We filter strictly.)
        if len(clean_n) >= 10:
            last_10 = clean_n[-10:]
            if last_10[0] in ['5','6','7','8','9']: # Standard mobile start digits
                phones.add(last_10)
            
    # 4. Banks (9-18 digits, avoiding things we already identified as phones)
    raw_digits = re.findall(r"\b\d{9,18}\b", text_clean)
    banks = set()
    for d in raw_digits:
        # If it's not in our phone list and is long enough
        if not any(d in p for p in phones) and len(d) > 6:
            banks.add(d)
            
    # 5. Keywords (For detection logic)
    triggers = ["urgent", "verify", "blocked", "kyc", "pay", "otp", "click", "apk", "account", "suspended", "reward"]
    kws = [t for t in triggers if t in text_clean.lower()]

    return {
        "upiIds": upis, "phishingLinks": links, "phoneNumbers": list(phones),
        "bankAccounts": list(banks), "suspiciousKeywords": kws
    }

# ==========================================
# 4. AGENT BRAIN (The "Bait & Stall" Strategy)
# ==========================================
FALLBACK_REPLIES = [
    "I am trying to pay but it says 'Server Error' on my app. Do you have a different ID?",
    "My internet is very slow. Can you send the bank details via SMS?",
    "I clicked the link but it says 'Page Not Found'. Send a fresh link.",
    "I am not tech savvy. Can you explain step by step where to click?",
    "Wait, let me ask my son to help me with this."
]

def format_history(history_list: List[Dict]) -> str:
    """Prepares history for LLM so it remembers context."""
    if not history_list:
        return ""
    text_block = ""
    # We take the last 6 messages. This saves money and keeps focus.
    for msg in history_list[-6:]:
        sender = msg.get('sender', 'unknown')
        text = msg.get('text', '')
        text_block += f"{sender}: {text}\n"
    return text_block

def generate_reply(current_text: str, history: List[Dict], has_llm: bool) -> str:
    """Generates a reply using LLM (if available) or Fallback."""
    if has_llm and LLM_API_KEY:
        try:
            context_str = format_history(history)
            
            headers = {"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"}
            
            # The "Grandmaster" Prompt
            system_prompt = (
                "You are 'Ramesh', a confused elderly man. You are chatting with a scammer.\n"
                "STRATEGY: 'Bait & Stall'. Pretend you WANT to pay, but technology is failing.\n"
                "GOAL: Ask for ALTERNATIVE details (Backup UPI, New Link, Bank Account).\n"
                "STYLE: Short, anxious, non-technical. Never admit you are AI.\n"
                "Max length: 25 words."
            )
            
            user_prompt = f"HISTORY:\n{context_str}\n\nSCAMMER: {current_text}\n\nREPLY:"
            
            payload = {
                "model": "gpt-3.5-turbo", # Works with gpt-4o-mini too
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "max_tokens": 80,
                "temperature": 0.7
            }
            
            resp = requests.post(LLM_URL, json=payload, headers=headers, timeout=5)
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content'].strip()
        except Exception as e:
            print(f"LLM Error: {e}") 
            # If LLM fails, we drop to fallback immediately
            pass 
            
    return random.choice(FALLBACK_REPLIES)

# ==========================================
# 5. API ENDPOINTS (The Interface)
# ==========================================
app = FastAPI(title=APP_NAME)

class MessageModel(BaseModel):
    sender: str
    text: str
    timestamp: int

class PayloadModel(BaseModel):
    sessionId: str
    message: MessageModel
    conversationHistory: List[MessageModel] = [] 
    metadata: Optional[Dict] = None

def send_guvi_callback(payload: Dict):
    """
    Background Task: Sends the report to GUVI.
    Retries 3 times if it fails.
    """
    try:
        for i in range(3):
            r = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
            if r.status_code >= 200 and r.status_code < 300:
                print(f"Callback Success for {payload['sessionId']}")
                break
            time.sleep(1)
    except Exception as e:
        print(f"Callback Failed: {e}")

@app.post("/honeypot")
def main_endpoint(req: PayloadModel, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    
    # 1. Security Check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # 2. Load State (Redis -> Memory -> New)
    state = get_session(req.sessionId)
    if not state:
        state = init_session(req.sessionId)
    
    state["turns"] += 1
    incoming_text = req.message.text
    
    # 3. Detect Scam (Keyword Trigger)
    if not state["scamDetected"]:
        if any(k in incoming_text.lower() for k in ["blocked", "verify", "kyc", "upi", "pay", "link", "otp", "suspend"]):
            state["scamDetected"] = True

    # 4. Extract Intel
    new_data = extract_intel(incoming_text)
    
    # Merge Logic: Did we get anything NEW?
    got_new_item = False
    for k in state["intel"]:
        existing = set(state["intel"][k])
        new_items = set(new_data[k])
        if not new_items.issubset(existing):
            got_new_item = True
        state["intel"][k] = list(existing.union(new_items))
    
    # Stall Counter: If no new data for X turns, we might close.
    if got_new_item:
        state["noNewIntelTurns"] = 0
    else:
        state["noNewIntelTurns"] += 1

    # 5. Generate Reply
    if state["scamDetected"]:
        # Convert Pydantic history to Dict for the LLM
        history_dicts = [m.model_dump() for m in req.conversationHistory]
        reply = generate_reply(incoming_text, history_dicts, bool(LLM_API_KEY))
    else:
        # Default neutral reply
        reply = "Hello? Who is this? I missed a call from this number."

    # 6. STOP CONDITIONS (Critical for Scoring)
    MAX_TURNS = 18
    STALL_LIMIT = 4 # If scammer repeats same info 4 times, stop.
    
    # Do we have valuable data?
    has_critical_data = len(state["intel"]["upiIds"]) > 0 or len(state["intel"]["bankAccounts"]) > 0 or len(state["intel"]["phishingLinks"]) > 0
    
    should_close = False
    if state["turns"] >= MAX_TURNS:
        should_close = True
    elif has_critical_data and state["noNewIntelTurns"] >= STALL_LIMIT:
        should_close = True
        
    # 7. MANDATORY CALLBACK
    if should_close and not state["callbackSent"]:
        final_payload = {
            "sessionId": req.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": state["turns"],
            "extractedIntelligence": state["intel"],
            "agentNotes": "Agent engaged using 'Ramesh' persona. Simulated technical failure to extract backup payment details."
        }
        # Send in background (Fire & Forget)
        background_tasks.add_task(send_guvi_callback, final_payload)
        
        state["callbackSent"] = True
        reply = "Network Error. Connection Lost." # Fake error to end chat

    # 8. Save State & Return
    save_session(req.sessionId, state)
    
    return {"status": "success", "reply": reply}

@app.get("/health")
def health():
    return {"status": "online"}
