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

# Optional Redis (falls back to memory if empty)
REDIS_URL = os.getenv("REDIS_URL", "")

# ==========================================
# 2. STATE MANAGEMENT (REDIS + MEMORY FALLBACK)
# ==========================================
MEMORY_DB = {}

def get_session(session_id: str):
    if REDIS_URL:
        try:
            import redis
            r = redis.from_url(REDIS_URL, decode_responses=True)
            data = r.get(session_id)
            return json.loads(data) if data else None
        except Exception as e:
            print("STATE: redis get failed:", str(e))
    return MEMORY_DB.get(session_id)

def save_session(session_id: str, data: Dict):
    if REDIS_URL:
        try:
            import redis
            r = redis.from_url(REDIS_URL, decode_responses=True)
            r.setex(session_id, 21600, json.dumps(data))  # 6 hours
            return
        except Exception as e:
            print("STATE: redis set failed:", str(e))
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
UPI_RE = re.compile(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}")
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
# Catch bare short links like bit.ly/fakebanksecure (no scheme)
BARE_DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s\]]+)?\b")
# De-cloaking indian phone numbers like +91 9 8 7 6 5...
LOOSE_PHONE_RE = re.compile(r"(?:\+?91|0)?[-\s]?(?:\d[-\s]?){10}")

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "kyc", "otp", "pin", "upi",
    "collect", "refund", "reward", "lottery", "click", "link", "apk",
    "anydesk", "teamviewer", "quicksupport", "password", "expire"
]

def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if len(digits) >= 10:
        last10 = digits[-10:]
        if last10 and last10[0] in ["5", "6", "7", "8", "9"]:
            return last10
    return ""

def extract_intel(text: str) -> Dict[str, List[str]]:
    text_clean = re.sub(r"\s+", " ", text).strip()

    upis = set(UPI_RE.findall(text_clean))

    urls = set(URL_RE.findall(text_clean))
    # also catch bare domains if they weren't caught by URL_RE
    bare = set(BARE_DOMAIN_RE.findall(text_clean))
    # avoid adding plain words; keep only ones that look link-ish
    # (this still may catch "SBI.com" etc, which is acceptable for hackathon)
    urls.update(bare)

    phones = set()
    for p in LOOSE_PHONE_RE.findall(text_clean):
        n = normalize_phone(p)
        if n:
            phones.add(n)

    # Bank accounts: 9–18 digits (avoid phone numbers)
    potential_banks = re.findall(r"\b\d{9,18}\b", text_clean)
    bank_accounts = set()
    for num in potential_banks:
        if num not in phones:
            bank_accounts.add(num)

    found_keywords = {k for k in SUSPICIOUS_KEYWORDS if k in text_clean.lower()}

    return {
        "upiIds": list(upis),
        "bankAccounts": list(bank_accounts),
        "phoneNumbers": list(phones),
        "phishingLinks": list(urls),
        "suspiciousKeywords": list(found_keywords)
    }

# ==========================================
# 4. AGENT REPLIES (SAFE FALLBACK)
# ==========================================
FALLBACK_REPLIES = [
    "I am trying to pay but it says 'Server Error' on my app. Do you have a different ID?",
    "My internet is very slow. Can you send the bank details via SMS?",
    "I clicked the link but it says 'Page Not Found'. Send a fresh link.",
    "I am not tech savvy. Can you explain step by step where to click?",
    "Wait, let me ask my son to help me with this."
]

def generate_reply() -> str:
    return random.choice(FALLBACK_REPLIES)

# ==========================================
# 5. FASTAPI MODELS
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
# 6. MANDATORY GUVI CALLBACK
# ==========================================
def send_guvi_callback(payload: Dict):
    # Very explicit logs so you can verify in Render logs
    print("GUVI_CALLBACK: sending for sessionId=", payload.get("sessionId"))

    try:
        for attempt in range(1, 4):
            r = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
            print("GUVI_CALLBACK: attempt", attempt, "status=", r.status_code)

            if 200 <= r.status_code < 300:
                print("GUVI_CALLBACK: success for sessionId=", payload.get("sessionId"))
                return

            time.sleep(1)

        print("GUVI_CALLBACK: failed after retries for sessionId=", payload.get("sessionId"))

    except Exception as e:
        print("GUVI_CALLBACK: exception:", str(e))

# ==========================================
# 7. MAIN ENDPOINT
# ==========================================
@app.post("/honeypot")
def honeypot(req: PayloadModel, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):

    # Auth
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Load session
    state = get_session(req.sessionId)
    if not state:
        state = init_session(req.sessionId)

    state["turns"] += 1
    incoming_text = req.message.text

    # Scam detection trigger
    if not state["scamDetected"]:
        if any(k in incoming_text.lower() for k in ["blocked", "verify", "kyc", "upi", "pay", "link", "otp", "suspend", "suspended"]):
            state["scamDetected"] = True

    # Extract intel
    delta = extract_intel(incoming_text)

    got_new_item = False
    for k in state["intel"]:
        existing = set(state["intel"][k])
        new_items = set(delta[k])
        if not new_items.issubset(existing):
            got_new_item = True
        state["intel"][k] = list(existing.union(new_items))

    if got_new_item:
        state["noNewIntelTurns"] = 0
    else:
        state["noNewIntelTurns"] += 1

    # Reply
    if state["scamDetected"]:
        reply = generate_reply()
    else:
        reply = "Hello? Who is this? I missed a call from this number."

    # Stop conditions
    MAX_TURNS = 18
    STALL_LIMIT = 4

    has_critical_data = (
        len(state["intel"]["upiIds"]) > 0
        or len(state["intel"]["bankAccounts"]) > 0
        or len(state["intel"]["phishingLinks"]) > 0
        or len(state["intel"]["phoneNumbers"]) > 0
    )

    should_close = False
    if state["turns"] >= MAX_TURNS:
        should_close = True
    elif has_critical_data and state["noNewIntelTurns"] >= STALL_LIMIT:
        should_close = True

    # Mandatory callback (send once)
    if should_close and not state["callbackSent"]:
        final_payload = {
            "sessionId": req.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": state["turns"],
            "extractedIntelligence": state["intel"],
            "agentNotes": "Scammer used urgency and credential/payment redirection tactics."
        }

        background_tasks.add_task(send_guvi_callback, final_payload)
        state["callbackSent"] = True

        # End chat message (fake failure)
        reply = "Network Error. Connection Lost."

    save_session(req.sessionId, state)
    return {"status": "success", "reply": reply}

@app.get("/health")
def health():
    return {"status": "online"}
