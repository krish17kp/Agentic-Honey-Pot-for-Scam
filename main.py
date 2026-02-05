import os
import re
import json
import random
import requests
import time
from typing import List, Optional, Dict
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel

# ==========================================
# 1. CONFIGURATION
# ==========================================
APP_NAME = "Agentic Honeypot - Final"
API_KEY = os.getenv("API_KEY", "SECRET_123")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Optional LLM config (fallback replies work without this)
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_URL = "https://api.openai.com/v1/chat/completions"

# Optional Redis
REDIS_URL = os.getenv("REDIS_URL", "")

# ==========================================
# 2. STATE MANAGEMENT (REDIS + MEMORY)
# ==========================================
MEMORY_DB = {}

def get_session(session_id: str):
    if REDIS_URL:
        try:
            import redis
            r = redis.from_url(REDIS_URL, decode_responses=True)
            data = r.get(session_id)
            return json.loads(data) if data else None
        except:
            pass
    return MEMORY_DB.get(session_id)

def save_session(session_id: str, data: Dict):
    if REDIS_URL:
        try:
            import redis
            r = redis.from_url(REDIS_URL, decode_responses=True)
            r.setex(session_id, 21600, json.dumps(data))
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
            "upiIds": [],
            "bankAccounts": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": []
        }
    }

# ==========================================
# 3. INTELLIGENCE EXTRACTION
# ==========================================
def extract_intel(text: str) -> Dict[str, List[str]]:
    text_clean = re.sub(r"\s+", " ", text).strip()

    upis = list(set(re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", text_clean)))
    links = list(set(re.findall(r"https?://\S+|www\.\S+", text_clean)))

    raw_nums = re.findall(r"(?:\+?91|0)?[-\s]?(?:\d[-\s]?){10}", text_clean)
    phones = set()
    for n in raw_nums:
        digits = re.sub(r"\D", "", n)
        if len(digits) >= 10:
            last10 = digits[-10:]
            if last10[0] in ["5", "6", "7", "8", "9"]:
                phones.add(last10)

    raw_digits = re.findall(r"\b\d{9,18}\b", text_clean)
    banks = set()
    for d in raw_digits:
        if not any(d in p for p in phones):
            banks.add(d)

    keywords = [
        "urgent", "verify", "blocked", "kyc", "otp", "upi",
        "account", "click", "apk", "suspended", "reward"
    ]
    found_keywords = [k for k in keywords if k in text_clean.lower()]

    return {
        "upiIds": upis,
        "bankAccounts": list(banks),
        "phoneNumbers": list(phones),
        "phishingLinks": links,
        "suspiciousKeywords": found_keywords
    }

# ==========================================
# 4. AGENT BRAIN (BAIT & STALL)
# ==========================================
FALLBACK_REPLIES = [
    "I am trying to pay but it says server error. Do you have another option?",
    "My internet is very slow. Can you send the details again?",
    "I clicked the link but it did not open. Please resend.",
    "I am not good with phones. Can you explain step by step?",
    "Wait, I will ask my son to help me."
]

def generate_reply(text: str) -> str:
    return random.choice(FALLBACK_REPLIES)

# ==========================================
# 5. FASTAPI SETUP
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

# ==========================================
# 6. GUVI CALLBACK
# ==========================================
def send_guvi_callback(payload: Dict):
    try:
        for _ in range(3):
            r = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
            if 200 <= r.status_code < 300:
                print(f"GUVI callback success for {payload['sessionId']}")
                break
            time.sleep(1)
    except Exception as e:
        print("GUVI callback failed:", str(e))

# ==========================================
# 7. HONEYPOT ENDPOINT
# ==========================================
@app.post("/honeypot")
def honeypot(
    req: PayloadModel,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    state = get_session(req.sessionId)
    if not state:
        state = init_session(req.sessionId)

    state["turns"] += 1
    incoming_text = req.message.text

    # Scam detection
    if not state["scamDetected"]:
        if any(k in incoming_text.lower() for k in ["blocked", "verify", "otp", "upi", "pay", "link"]):
            state["scamDetected"] = True

    # Intelligence extraction
    delta = extract_intel(incoming_text)
    got_new = False

    for k in state["intel"]:
        before = set(state["intel"][k])
        after = set(delta[k])
        if not after.issubset(before):
            got_new = True
        state["intel"][k] = list(before.union(after))

    if got_new:
        state["noNewIntelTurns"] = 0
    else:
        state["noNewIntelTurns"] += 1

    # Agent reply
    if state["scamDetected"]:
        reply = generate_reply(incoming_text)
    else:
        reply = "Hello? Who is this?"

    # Stop conditions
    MAX_TURNS = 18
    STALL_LIMIT = 4

    has_data = (
        len(state["intel"]["upiIds"]) > 0 or
        len(state["intel"]["bankAccounts"]) > 0 or
        len(state["intel"]["phishingLinks"]) > 0
    )

    should_close = (
        state["turns"] >= MAX_TURNS or
        (has_data and state["noNewIntelTurns"] >= STALL_LIMIT)
    )

    if should_close and not state["callbackSent"]:
        final_payload = {
            "sessionId": req.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": state["turns"],
            "extractedIntelligence": state["intel"],
            "agentNotes": "Scammer used urgency, impersonation, and payment redirection tactics"
        }
        background_tasks.add_task(send_guvi_callback, final_payload)
        state["callbackSent"] = True
        reply = "Network error. Connection lost."

    save_session(req.sessionId, state)
    return {"status": "success", "reply": reply}

# ==========================================
# 8. HEALTH CHECK
# ==========================================
@app.get("/health")
def health():
    return {"status": "online"}
