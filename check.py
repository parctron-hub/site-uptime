#!/usr/bin/env python3
"""Проверка доступности сайтов и сборка данных для табло.

Запускается GitHub Actions каждые 30 минут (см. .github/workflows/check.yml),
можно запустить и руками: python check.py

Что считается «доступен»: HTTP 200 И полный HTML (больше MIN_BYTES байт).
Заглушка Beget (274 байта, код 200) и страница-ошибка DDoS-Guard — это НЕ
доступен. Один повтор через RETRY_AFTER секунд, чтобы не поднимать тревогу
из-за единичного сбоя сети.

Пишет:
  docs/data/history.jsonl — одна строка на сайт на проверку, хранится DAYS_KEEP дней
  docs/data/status.json   — сводка для табло (docs/index.html)
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
import ssl
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

SITES = [
    {"id": "centrfenix", "name": "centrfenix.ru", "url": "https://centrfenix.ru/"},
    {"id": "fenix-siz", "name": "fenix-siz.ru", "url": "https://fenix-siz.ru/"},
    {"id": "ncarus", "name": "ncarus.ru", "url": "https://ncarus.ru/"},
    {"id": "csb-fenix", "name": "csb-fenix.ru", "url": "https://csb-fenix.ru/"},
    # добавлены 06.11.2026: живут на другом сервере (45.130.41.14), не на Beget
    {"id": "check-centrfenix", "name": "check.centrfenix.ru", "url": "https://check.centrfenix.ru/"},
    {"id": "check-fenix-siz", "name": "check.fenix-siz.ru", "url": "https://check.fenix-siz.ru/"},
]

TIMEOUT = 30          # секунд на один запрос
RETRY_AFTER = 15      # пауза перед повтором при сбое
MIN_BYTES = 5000      # меньше — заглушка или страница ошибки, не сайт
SLOW_MS = 5000        # дольше — «медленно»
DAYS_KEEP = 90
STRIP_POINTS = 48     # сколько последних проверок рисовать в полоске (48 × 30 мин = сутки)

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "docs" / "data"
HISTORY = DATA / "history.jsonl"
STATUS = DATA / "status.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 site-uptime/1.0",
    "Cookie": "beget=begetok",
    "Accept": "text/html,*/*;q=0.8",
    "Accept-Language": "ru,en;q=0.5",
}


def fetch(url: str) -> dict:
    """Один запрос. Возвращает code, ms, bytes, err."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=HEADERS)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            body = r.read()
            ms = int((time.perf_counter() - t0) * 1000)
            return {"code": r.status, "ms": ms, "bytes": len(body), "err": ""}
    except urllib.error.HTTPError as e:
        ms = int((time.perf_counter() - t0) * 1000)
        try:
            n = len(e.read())
        except Exception:
            n = 0
        return {"code": e.code, "ms": ms, "bytes": n, "err": f"HTTP {e.code}"}
    except Exception as e:  # таймаут, DNS, TLS, отказ соединения
        ms = int((time.perf_counter() - t0) * 1000)
        name = type(e).__name__
        msg = str(e).strip() or name
        if "timed out" in msg.lower() or name == "timeout":
            msg = f"таймаут {TIMEOUT} с"
        return {"code": 0, "ms": ms, "bytes": 0, "err": msg[:120]}


def classify(r: dict) -> str:
    if r["code"] == 200 and r["bytes"] >= MIN_BYTES:
        return "slow" if r["ms"] > SLOW_MS else "up"
    return "down"


def check_site(site: dict) -> dict:
    r = fetch(site["url"])
    state = classify(r)
    attempts = 1
    if state == "down":
        time.sleep(RETRY_AFTER)
        r2 = fetch(site["url"])
        attempts = 2
        if classify(r2) != "down":
            r, state = r2, classify(r2)
        else:
            r = r2
    if state == "down" and r["code"] == 200 and 0 < r["bytes"] < MIN_BYTES:
        r["err"] = f"код 200, но тело {r['bytes']} байт — заглушка, не сайт"
    return {"site": site["id"], "state": state, "attempts": attempts, **r}


def load_history() -> list:
    if not HISTORY.exists():
        return []
    out = []
    with HISTORY.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def save_history(rows: list) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    with HISTORY.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def parse_t(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def uptime(rows: list, since: datetime):
    sel = [r for r in rows if parse_t(r["t"]) >= since]
    if not sel:
        return None
    ok = sum(1 for r in sel if r["state"] != "down")
    return round(100.0 * ok / len(sel), 2)


def incidents(rows: list, limit: int = 10) -> list:
    """Подряд идущие проверки со state=down → один инцидент."""
    out = []
    cur = None
    for r in rows:  # rows отсортированы по времени
        if r["state"] == "down":
            if cur is None:
                cur = {"start": r["t"], "end": r["t"], "checks": 1, "err": r.get("err", "")}
            else:
                cur["end"] = r["t"]
                cur["checks"] += 1
        else:
            if cur is not None:
                cur["resolved"] = True
                out.append(cur)
                cur = None
    if cur is not None:
        cur["resolved"] = False
        out.append(cur)
    return out[-limit:][::-1]


def build_status(rows: list, now: datetime) -> dict:
    by_site = {s["id"]: [] for s in SITES}
    for r in rows:
        if r["site"] in by_site:
            by_site[r["site"]].append(r)
    sites_out = []
    for s in SITES:
        sr = sorted(by_site[s["id"]], key=lambda r: r["t"])
        last = sr[-1] if sr else None
        okms = [r["ms"] for r in sr if r["state"] != "down" and parse_t(r["t"]) >= now - timedelta(days=1)]
        sites_out.append({
            "id": s["id"], "name": s["name"], "url": s["url"],
            "state": last["state"] if last else "unknown",
            "last": last,
            "uptime_24h": uptime(sr, now - timedelta(days=1)),
            "uptime_7d": uptime(sr, now - timedelta(days=7)),
            "uptime_30d": uptime(sr, now - timedelta(days=30)),
            "avg_ms_24h": int(sum(okms) / len(okms)) if okms else None,
            "strip": [[r["t"], r["state"], r["ms"], r["code"], r.get("err", "")] for r in sr[-STRIP_POINTS:]],
            "incidents": incidents(sr),
        })
    return {
        "generated": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "interval_min": 30,
        "rules": {"min_bytes": MIN_BYTES, "slow_ms": SLOW_MS, "timeout_s": TIMEOUT},
        "sites": sites_out,
    }


# ---------- Telegram ----------
# Токен и чат берутся из переменных окружения (в GitHub — Secrets репозитория):
#   TELEGRAM_BOT_TOKEN — токен от @BotFather
#   TELEGRAM_CHAT_ID   — id личного чата или группы (у группы отрицательный)
# Без них уведомления молча отключены. Пишем только при смене состояния:
# «работал → упал» и «лежал → поднялся»; «медленно» считается «работает».
LOCAL_TZ = timezone(timedelta(hours=5))  # UTC+5, Москва +2 ч — часовой пояс пользователя


def tg_send(text: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat:
        return
    data = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "1"}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        print("telegram: отправлено", flush=True)
    except Exception as e:  # уведомление не должно ронять проверку
        print(f"telegram: не отправлено — {str(e)[:120]}", flush=True)


def fmt_local(t: str) -> str:
    return parse_t(t).astimezone(LOCAL_TZ).strftime("%d.%m %H:%M")


def fmt_dur(seconds: int) -> str:
    m = seconds // 60
    if m < 60:
        return f"{m} мин"
    h, m = divmod(m, 60)
    return f"{h} ч {m:02d} мин"


def notify_changes(prev_rows: list, results: list) -> None:
    """Сравнивает состояние каждого сайта с прошлой проверкой и шлёт в Telegram."""
    last = {}
    for r in prev_rows:  # отсортированы по времени → останется последняя
        last[r["site"]] = r
    down_since = {}
    for r in prev_rows:  # начало текущего падения: первая down-проверка подряд
        if r["state"] == "down":
            down_since.setdefault(r["site"], r["t"])
        else:
            down_since.pop(r["site"], None)
    names = {s["id"]: s["name"] for s in SITES}
    lines = []
    for r in results:
        was = last.get(r["site"], {}).get("state")
        now_down = r["state"] == "down"
        was_down = was == "down"
        if was is None or now_down == was_down:
            continue
        name = names.get(r["site"], r["site"])
        if now_down:
            why = r["err"] or f"код {r['code']}"
            lines.append(f"🔴 {name} недоступен с {fmt_local(r['t'])} (UTC+5) — {why}")
        else:
            start = down_since.get(r["site"], last[r["site"]]["t"])
            dur = int((parse_t(r["t"]) - parse_t(start)).total_seconds())
            lines.append(f"🟢 {name} снова работает ({r['ms']} мс), простой {fmt_dur(dur)}")
    if lines:
        tg_send("\n".join(lines) + "\n\nТабло: https://parctron-hub.github.io/site-uptime/")


def main() -> int:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    stamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    results = []
    for s in SITES:
        r = check_site(s)
        r["t"] = stamp
        results.append(r)
        print(f"{s['name']:16} {r['state']:5} code={r['code']} {r['ms']} ms {r['bytes']} B "
              f"{'повтор ' if r['attempts'] > 1 else ''}{r['err']}", flush=True)

    prev_rows = load_history()
    prev_rows.sort(key=lambda r: (r["t"], r["site"]))
    notify_changes(prev_rows, results)

    rows = prev_rows + results
    cutoff = now - timedelta(days=DAYS_KEEP)
    rows = [r for r in rows if parse_t(r["t"]) >= cutoff]
    rows.sort(key=lambda r: (r["t"], r["site"]))
    save_history(rows)

    STATUS.write_text(json.dumps(build_status(rows, now), ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
