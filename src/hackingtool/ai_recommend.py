"""Opt-in AI + stdlib fallback: free-text intent -> catalog tags.

Guardrail: the model only ever returns tags from the closed ``TAXONOMY``; the
catalog resolves tags -> tools, so a tool can never be fabricated. Any tag the
model returns that is not in ``TAXONOMY`` is dropped. With no model reachable it
degrades to a stdlib keyword matcher.

Transport (opt-in): provider/model/base-url come from ``config`` (set via
``/config`` or ``HACKINGTOOL_AI_*`` env/.env; env wins). ``ai_provider`` picks
BYO-key OpenAI-compatible endpoint vs local Ollama; the API key is env/.env only.
"""
import difflib
import json
import re
import urllib.error
import urllib.request

from hackingtool import config, skill
from hackingtool.tags import TAXONOMY

def _ollama_url() -> str:
    """Return the Ollama API URL, using config.ai_base_url() if set, else default."""
    base = config.ai_base_url()
    if base:
        return base.rstrip("/") + "/api/generate"
    return "http://127.0.0.1:11434/api/generate"


# Backward compatibility - deprecated, use _ollama_url() instead
_OLLAMA_URL = _ollama_url()

# Shared operator charter (persona + safety + anti-fabrication) + AI1 output contract.
_PROMPT = skill.charter() + "\n\n" + (
    "Task: map a security task to tags. Pick the tags from the ALLOWED list that "
    "best match the user's task. Reply with ONLY a JSON array of tag strings "
    "taken from the ALLOWED list, nothing else.\n"
    "ALLOWED: {allowed}\nTASK: {intent}\n"
)

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def _parse_tags(reply: str | None) -> list[str]:
    """Pull a JSON array of strings from a model reply; keep only real tags."""
    if not isinstance(reply, str) or not reply:   # None / non-str content → no tags
        return []
    m = re.search(r"\[.*\]", reply, re.DOTALL)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
    except ValueError:
        return []
    return [t for t in arr if isinstance(t, str) and t in TAXONOMY]


def _ollama(prompt: str) -> str | None:
    payload = json.dumps({"model": config.ai_model(), "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(_ollama_url(), data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read()).get("response")
    except (urllib.error.URLError, OSError, ValueError, AttributeError):
        return None


def _byo_key(prompt: str) -> str | None:
    """OpenAI-compatible chat completion (OpenAI / Groq / local, etc.). Base URL from
    config; key is env/.env only. Returns None when either is unset."""
    base = config.ai_base_url()
    key = config.ai_key()
    if not (base and key):
        return None
    url = base.rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": config.ai_model(),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }).encode()
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        content = data["choices"][0]["message"]["content"]
        return content if isinstance(content, str) else None   # null/tool-call content → None
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError):
        return None


def ask(prompt: str) -> str | None:
    """Opt-in transport gated by config ``ai_provider``: 'auto' tries BYO-key then
    Ollama (current behaviour); 'ollama' forces local; 'openai-compat' forces BYO.
    ``None`` when nothing is reachable."""
    provider = config.ai_provider()
    reply = None
    if provider != "ollama":
        reply = _byo_key(prompt)
    if reply is None and provider != "openai-compat":
        reply = _ollama(prompt)
    return reply


def test_connection() -> tuple[bool, str]:
    """Probe the configured transport with a tiny prompt and surface the real
    failure reason (HTTP status / unreachable) instead of ask()'s silent None.
    Returns (ok, human-readable detail). Mirrors ask()'s provider selection."""
    provider = config.ai_provider()
    use_byo = provider == "openai-compat" or (
        provider == "auto" and bool(config.ai_base_url()) and bool(config.ai_key()))
    if not use_byo:
        return _probe_ollama()
    ok, detail = _probe_byo()
    if ok or provider != "auto":
        return ok, detail
    # auto mode mirrors ask(): BYO failed → fall back to local Ollama before reporting failure
    ok2, detail2 = _probe_ollama()
    if ok2:
        return True, f"{detail2} (remote failed: {detail})"
    return False, f"{detail}; Ollama fallback also failed: {detail2}"


def _probe_byo() -> tuple[bool, str]:
    base, key, model = config.ai_base_url(), config.ai_key(), config.ai_model()
    if not base:
        return False, "ai_base_url is empty — set it via /config (e.g. https://api.anthropic.com/v1)."
    if not key:
        return False, "HACKINGTOOL_AI_KEY is not set — add it to ~/.hackingtool/.env."
    url = base.rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": model, "max_tokens": 16, "temperature": 0,
        "messages": [{"role": "user", "content": "Reply with the single word: connected"}],
    }).encode()
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = json.loads(resp.read())["choices"][0]["message"]["content"]
        if not isinstance(content, str):          # null / tool-call content isn't a usable reply
            return False, f"unexpected response from {url} — content was {type(content).__name__}, not text"
        return True, f"{model} replied {content.strip()!r}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code} from {url} — {e.read().decode(errors='replace')[:200]}"
    except (urllib.error.URLError, OSError) as e:
        return False, f"cannot reach {url} — {e}"
    except (ValueError, KeyError, IndexError) as e:
        return False, f"unexpected response from {url} — {e}"


def _probe_ollama() -> tuple[bool, str]:
    model = config.ai_model()
    payload = json.dumps({"model": model, "prompt": "Reply with: connected", "stream": False}).encode()
    url = _ollama_url()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            reply = (json.loads(resp.read()).get("response") or "").strip()
        return True, f"ollama {model} replied {reply!r}"
    except urllib.error.HTTPError as e:
        return False, (f"HTTP {e.code} from Ollama — is model '{model}' pulled? "
                       f"({e.read().decode(errors='replace')[:150]})")
    except (urllib.error.URLError, OSError) as e:
        return False, f"cannot reach Ollama at {_OLLAMA_URL} — is it running? ({e})"
    except (ValueError, AttributeError) as e:
        return False, f"unexpected Ollama response — {e}"


def suggest_tags(intent: str) -> list[str] | None:
    """AI leg: intent -> taxonomy tags. ``None`` when no model is reachable."""
    reply = ask(_PROMPT.format(allowed=", ".join(sorted(TAXONOMY)), intent=intent))
    if reply is None:
        return None
    return _parse_tags(reply)


def keyword_match(intent: str, tags, limit: int = 6) -> list[str]:
    """Rank ``tags`` by token overlap with the intent (stdlib only)."""
    words = _tokens(intent)
    if not words:
        return []
    scored = []
    for tag in tags:
        score = 0.0
        for tw in _WORD.findall(tag.lower()):
            if tw in words:
                score += 2.0
            elif difflib.get_close_matches(tw, words, n=1, cutoff=0.8):
                score += 1.0  # extract ~ extraction, wifi ~ wi-fi, etc.
        if score:
            scored.append((score, tag))
    scored.sort(key=lambda s: (-s[0], s[1]))
    return [tag for _, tag in scored[:limit]]


def resolve(intent: str, tags) -> list[str]:
    """Intent -> tags: AI leg if reachable, else keyword fallback. Never empty-fabricates."""
    picked = suggest_tags(intent)
    if not picked:
        picked = keyword_match(intent, tags)
    return picked


def demo() -> None:
    # Guardrail: fabricated tags are dropped, only real taxonomy tags survive.
    assert _parse_tags('noise ["hash-crack", "totally-made-up"] tail') == ["hash-crack"]
    assert _parse_tags("no array here") == []
    assert _parse_tags(None) == []
    # Keyword fallback is deterministic and offline.
    assert "hash-crack" in keyword_match("crack a hash", TAXONOMY)
    assert "pdf-extraction" in keyword_match("extract text from a pdf", TAXONOMY)
    assert keyword_match("", TAXONOMY) == []
    print("OK — ai_recommend: parse guardrail + offline keyword fallback")


if __name__ == "__main__":
    demo()
