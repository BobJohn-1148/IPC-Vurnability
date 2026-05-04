# -*- coding: utf-8 -*-
"""
test_cases.py -- IPC Buffer Overflow Demo -- Extended Test Suite
Captures: response time, overflow bytes, stack corruption estimate,
          server status after send, return address state.
Includes 4 extended test types: Integration, Load, Error Condition, Environment.
"""

import socket, subprocess, time, os, json, threading

SAFE_SOCKET_PATH = "/tmp/ipc_demo_socket"
VULN_SOCKET_PATH = "/tmp/ipc_vuln_socket"
CMD_SIZE         = 16
PAYLOAD_SIZE     = 128
LOCAL_BUF_SIZE   = 32
RESULTS_JSON     = "test_results.json"
RESULTS_TXT      = "test_results.txt"

R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"
M  = "\033[95m"; C  = "\033[96m"; W  = "\033[97m"; NC = "\033[0m"

# ---------------------------------------------------------------------------
# IPC helpers
# ---------------------------------------------------------------------------

def make_ipc_message(command, payload):
    cmd_b     = command.encode()[:CMD_SIZE - 1].ljust(CMD_SIZE,  b'\x00')
    payload_b = payload.encode()[:PAYLOAD_SIZE - 1].ljust(PAYLOAD_SIZE, b'\x00')
    return cmd_b + payload_b

def send_ipc(sock_path, command, payload):
    msg = make_ipc_message(command, payload)
    t0  = time.perf_counter()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(sock_path)
            s.sendall(msg)
            data = s.recv(256)
            ms   = round((time.perf_counter() - t0) * 1000, 2)
            text = data.decode(errors="replace").rstrip('\x00')
            return {"status": "ERROR" if text.startswith("ERROR") else "OK",
                    "response": text, "response_ms": ms}
    except FileNotFoundError:
        return {"status": "NO_SERVER", "response": "Socket not found", "response_ms": -1}
    except ConnectionRefusedError:
        ms = round((time.perf_counter() - t0) * 1000, 2)
        return {"status": "CRASH",  "response": "Connection refused -- crashed", "response_ms": ms}
    except socket.timeout:
        ms = round((time.perf_counter() - t0) * 1000, 2)
        return {"status": "CRASH",  "response": "Timed out -- unresponsive",    "response_ms": ms}
    except Exception as e:
        ms = round((time.perf_counter() - t0) * 1000, 2)
        return {"status": "ERROR",  "response": str(e), "response_ms": ms}

def is_alive(sock_path):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(1); s.connect(sock_path); return True
    except Exception:
        return False

def start_server(binary, sock_path):
    proc = subprocess.Popen([binary],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        time.sleep(0.1)
        if os.path.exists(sock_path):
            return proc
    return proc

# ---------------------------------------------------------------------------
# Derived metrics
# ---------------------------------------------------------------------------

def overflow_bytes(payload):
    return max(0, len(payload.encode()) - LOCAL_BUF_SIZE)

def return_address_state(payload):
    ob = overflow_bytes(payload)
    if ob == 0:             return "Intact"
    if ob <= 8:             return "Saved RBP overwritten"
    return "Overwritten (0x41414141)"

def determine_verdict(server, payload, result):
    ob, stat, resp = overflow_bytes(payload), result["status"], result["response"]
    if server == "safe":
        if ob == 0 and stat == "OK":                         return "PASS"
        if ob > 0 and (stat == "ERROR" or "too large" in resp): return "PASS"
        if ob == 0 and stat == "ERROR" and "too large" in resp: return "PASS"
        return "FAIL"
    if ob == 0 and stat == "OK":   return "PASS"
    if ob > 0:                     return "OVERFLOW"
    return "FAIL"

# ---------------------------------------------------------------------------
# Core test definitions
# ---------------------------------------------------------------------------

SAFE_TESTS = [
    ("S01","Normal",       "Empty payload",                       "HELLO",""),
    ("S02","Normal",       "Single character",                    "HELLO","A"),
    ("S03","Normal",       "Short message (5 B)",                 "HELLO","Hello"),
    ("S04","Normal",       "Medium message (15 B)",               "MSG",  "Hello, server!"),
    ("S05","Boundary",     "10 B below limit (21 B)",             "HELLO","A"*21),
    ("S06","Boundary",     "5 B below limit (26 B)",              "HELLO","A"*26),
    ("S07","Boundary",     "1 B below limit (30 B)",              "HELLO","A"*30),
    ("S08","Boundary",     "Exactly at limit (31 B)",             "HELLO","A"*31),
    ("S09","Boundary",     "1 B over limit (32 B) -- rejected",  "HELLO","A"*32),
    ("S10","Overflow",     "8 B over limit (40 B) -- rejected",  "FLOOD","A"*40),
    ("S11","Overflow",     "Standard overflow attempt (48 B)",   "FLOOD","A"*48),
    ("S12","Max Payload",  "Max struct payload (127 B)",          "FLOOD","A"*127),
    ("S13","Special Chars","Punctuation and symbols",             "MSG",  "!@#$%^&*()-+=[]{}"),
    ("S14","Special Chars","Spaces and tab characters",           "MSG",  "hello world\ttab"),
    ("S15","Long Command", "Command > 16 B (truncated by struct)","VERYLONGCMDNAME","Short payload"),
    ("S16","Numeric",      "Numeric string payload",              "DATA", "1234567890"),
    ("S17","Cyclic Pattern","Repeating ABCD pattern (28 B)",      "PAT",  "ABCD"*7),
]

VULN_TESTS = [
    ("V01","Normal",       "Empty payload",                       "HELLO",""),
    ("V02","Normal",       "Single character",                    "HELLO","A"),
    ("V03","Normal",       "Short message (5 B)",                 "HELLO","Hello"),
    ("V04","Normal",       "Medium message (15 B)",               "MSG",  "Hello, server!"),
    ("V05","Boundary",     "1 B below limit (30 B)",              "HELLO","A"*30),
    ("V06","Boundary",     "Exactly at limit (31 B)",             "HELLO","A"*31),
    ("V07","Boundary",     "First overflow byte (32 B)",          "FLOOD","A"*32),
    ("V08","Boundary",     "1 B past saved RBP region (33 B)",   "FLOOD","A"*33),
    ("V09","Overflow",     "Overwrites saved RBP (40 B)",         "FLOOD","A"*40),
    ("V10","Overflow",     "Overwrites return address (48 B)",    "FLOOD","A"*48),
    ("V11","Overflow",     "Large overflow (64 B)",               "FLOOD","A"*64),
    ("V12","Overflow",     "Very large overflow (96 B)",          "FLOOD","A"*96),
    ("V13","Max Payload",  "Max struct payload (127 B)",          "FLOOD","A"*127),
    ("V14","Cyclic Pattern","De Bruijn-style pattern (48 B)",     "PAT",  "AAAABAAACAAADAAAEAAAFAAABAAACAAAAAAAAAAAA"[:48]),
    ("V15","Special Chars","Null-terminated short string",        "MSG",  "short"),
    ("V16","Numeric",      "Numeric string (10 B)",               "DATA", "1234567890"),
]

# ---------------------------------------------------------------------------
# Core test runner
# ---------------------------------------------------------------------------

def run_tests(server_label, sock_path, binary, tests):
    print(f"\n{W}{'='*72}{NC}")
    print(f"{W} {server_label}  ({len(tests)} test cases){NC}")
    print(f"{W}{'='*72}{NC}\n")
    results, proc = [], None
    for (tid, category, desc, cmd, payload) in tests:
        plen, ob = len(payload.encode()), overflow_bytes(payload)
        if not is_alive(sock_path):
            if proc:
                try: proc.wait(timeout=1)
                except: pass
            proc = start_server(binary, sock_path)
            time.sleep(0.2)
        result = send_ipc(sock_path, cmd, payload)
        time.sleep(0.05)
        alive_after  = is_alive(sock_path)
        server_after = "Running" if alive_after else "Crashed"
        verdict      = determine_verdict(
            "safe" if "Safe" in server_label else "vuln", payload, result)
        row = {
            "id": tid, "server": server_label, "category": category,
            "description": desc, "command": cmd, "payload_bytes": plen,
            "overflow_bytes": ob, "stack_corrupted": max(0, ob),
            "response_ms": result["response_ms"], "status": result["status"],
            "response": result["response"][:60], "server_after": server_after,
            "return_addr": return_address_state(payload), "verdict": verdict,
        }
        results.append(row)
        vc  = {"PASS":G,"FAIL":R,"OVERFLOW":M}.get(verdict, W)
        ms  = f"{result['response_ms']:6.1f} ms" if result["response_ms"] >= 0 else "   N/A  "
        ofs = f"+{ob}B" if ob > 0 else f"{plen}B"
        print(f"  {C}{tid}{NC}  {category:<16} {desc:<44} "
              f"{ofs:<8} {ms}  {vc}{verdict:<8}{NC}  {server_after}")
        time.sleep(0.05)
    if proc:
        proc.terminate()
    return results

# ---------------------------------------------------------------------------
# Extended test I01 -- Integration
# ---------------------------------------------------------------------------

def run_integration_test():
    """
    I01 -- Full Integration Test
    Answers: Does the whole system do what it is supposed to?
    Starts each server fresh, sends one valid message, verifies the response
    text is correct, checks the server stayed alive, then shuts down.
    Tests the complete pipeline: server startup -> socket binding -> message
    receive -> bounds check (or lack thereof) -> reply -> client receive.
    """
    print(f"\n{W}{'='*72}{NC}")
    print(f"{W} Extended Test I01 -- Full System Integration{NC}")
    print(f"{W}{'='*72}{NC}")
    cases = [
        ("Safe Server",       "./server",      SAFE_SOCKET_PATH,
         "Hello", "OK: message processed"),
        ("Vulnerable Server", "./server_vuln", VULN_SOCKET_PATH,
         "Hello", "OK: message stored"),
    ]
    sub, all_passed = [], True
    for label, binary, sock, payload, expect in cases:
        proc = start_server(binary, sock)
        time.sleep(0.2)
        r     = send_ipc(sock, "HELLO", payload)
        alive = is_alive(sock)
        passed = (r["status"] == "OK" and expect in r["response"] and alive)
        if not passed: all_passed = False
        v = G if passed else R
        print(f"  {label:<22}  RTT {r['response_ms']:.2f} ms  "
              f"Response: {r['response'][:45]}  {v}{'PASS' if passed else 'FAIL'}{NC}")
        sub.append({"server": label, "payload": payload,
                    "response": r["response"], "response_ms": r["response_ms"],
                    "server_after": "Running" if alive else "Crashed",
                    "passed": passed})
        proc.terminate(); time.sleep(0.1)
    verdict = "PASS" if all_passed else "FAIL"
    print(f"\n  Overall verdict: {G if all_passed else R}{verdict}{NC}")
    return {"sub_tests": sub, "verdict": verdict}

# ---------------------------------------------------------------------------
# Extended test L01 -- Load
# ---------------------------------------------------------------------------

def run_load_test(n=100):
    """
    L01 -- Load Test
    Answers: Can I bog it down with a ton of work?
    Fires n sequential messages at the safe server as fast as possible.
    Records total time, throughput (msg/s), min/avg/max RTT under load,
    error count, and whether the server survived all n requests.
    """
    print(f"\n{W}{'='*72}{NC}")
    print(f"{W} Extended Test L01 -- Load Test  ({n} sequential messages){NC}")
    print(f"{W}{'='*72}{NC}")
    proc = start_server("./server", SAFE_SOCKET_PATH)
    time.sleep(0.2)
    rtts, errors = [], 0
    t_start = time.perf_counter()
    for i in range(n):
        r = send_ipc(SAFE_SOCKET_PATH, "LOAD", f"msg{i:04d}")
        if r["status"] != "OK": errors += 1
        elif r["response_ms"] > 0: rtts.append(r["response_ms"])
    total_ms   = round((time.perf_counter() - t_start) * 1000, 2)
    throughput = round(n / (total_ms / 1000), 1)
    alive      = is_alive(SAFE_SOCKET_PATH)
    avg_rtt    = round(sum(rtts)/len(rtts), 2) if rtts else -1
    min_rtt    = round(min(rtts), 2)           if rtts else -1
    max_rtt    = round(max(rtts), 2)           if rtts else -1
    proc.terminate()
    verdict = "PASS" if errors == 0 and alive else "FAIL"
    print(f"  Messages sent    : {n}")
    print(f"  Errors           : {errors}")
    print(f"  Total time       : {total_ms} ms")
    print(f"  Throughput       : {throughput} msg/s")
    print(f"  Avg RTT          : {avg_rtt} ms")
    print(f"  Min RTT          : {min_rtt} ms")
    print(f"  Max RTT          : {max_rtt} ms")
    print(f"  Server survived  : {'Yes' if alive else 'No'}")
    print(f"  Verdict          : {G if verdict=='PASS' else R}{verdict}{NC}")
    return {"messages": n, "errors": errors, "total_ms": total_ms,
            "throughput": throughput, "avg_rtt": avg_rtt,
            "min_rtt": min_rtt, "max_rtt": max_rtt,
            "server_survived": alive, "verdict": verdict}

# ---------------------------------------------------------------------------
# Extended test ER01 -- Error Condition
# ---------------------------------------------------------------------------

def run_error_condition_test():
    """
    ER01 -- Error Condition Test
    Answers: Can I force an error condition upon it?
    Three sub-tests:
      a) Send a deliberately truncated struct (50 of 144 bytes).
         The server's recv() gets incomplete data -- tests graceful handling.
      b) Send a message with an all-null command field.
      c) Immediately follow with a valid message to verify server recovery.
    """
    print(f"\n{W}{'='*72}{NC}")
    print(f"{W} Extended Test ER01 -- Error Condition{NC}")
    print(f"{W}{'='*72}{NC}")
    proc = start_server("./server", SAFE_SOCKET_PATH)
    time.sleep(0.2)
    sub = []

    # ER01a: truncated struct
    t0 = time.perf_counter()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2); s.connect(SAFE_SOCKET_PATH)
            s.sendall(b"HELLO\x00" * 8)   # 48 bytes -- not a full 144-byte struct
            try:
                resp = s.recv(256).decode(errors="replace").rstrip('\x00') or "(empty)"
            except socket.timeout:
                resp = "TIMEOUT -- server waiting for rest of struct"
        ms    = round((time.perf_counter() - t0) * 1000, 2)
        alive = is_alive(SAFE_SOCKET_PATH)
        sub.append({"sub":"ER01a","desc":"Truncated struct (48 of 144 B)",
                    "response": resp[:60], "response_ms": ms,
                    "server_after": "Running" if alive else "Crashed"})
        print(f"  ER01a Truncated struct       RTT: {ms:.2f} ms  "
              f"{resp[:50]}  {'Running' if alive else f'{R}Crashed{NC}'}")
    except Exception as e:
        sub.append({"sub":"ER01a","desc":"Truncated struct","response":str(e),
                    "response_ms":-1,"server_after":"Unknown"})
        print(f"  ER01a Truncated struct       ERROR: {e}")

    # ER01b: null command field
    r2    = send_ipc(SAFE_SOCKET_PATH, "", "ValidPayload")
    alive2 = is_alive(SAFE_SOCKET_PATH)
    sub.append({"sub":"ER01b","desc":"All-null command field",
                "response": r2["response"][:60], "response_ms": r2["response_ms"],
                "server_after": "Running" if alive2 else "Crashed"})
    print(f"  ER01b Null command field     RTT: {r2['response_ms']:.2f} ms  "
          f"{r2['response'][:50]}  {'Running' if alive2 else f'{R}Crashed{NC}'}")

    # ER01c: recovery check
    r3    = send_ipc(SAFE_SOCKET_PATH, "HELLO", "RecoveryCheck")
    alive3 = is_alive(SAFE_SOCKET_PATH)
    sub.append({"sub":"ER01c","desc":"Recovery -- valid msg after error",
                "response": r3["response"][:60], "response_ms": r3["response_ms"],
                "server_after": "Running" if alive3 else "Crashed"})
    print(f"  ER01c Recovery check         RTT: {r3['response_ms']:.2f} ms  "
          f"{r3['response'][:50]}  {'Running' if alive3 else f'{R}Crashed{NC}'}")

    proc.terminate()
    overall = "PASS" if alive3 else "FAIL"
    print(f"  Overall verdict  : {G if overall=='PASS' else R}{overall}{NC}")
    return {"sub_tests": sub, "verdict": overall}

# ---------------------------------------------------------------------------
# Extended test SY01 -- Environment / System
# ---------------------------------------------------------------------------

def run_environment_test():
    """
    SY01 -- Environment / System Test
    Answers: Does the program behave differently if the environment is busy?
    Measures RTT under a clean baseline, then again while 4 CPU-burning
    threads saturate the processor. Captures avg/min/max for both phases
    and calculates the latency drift in ms and as a percentage.
    """
    print(f"\n{W}{'='*72}{NC}")
    print(f"{W} Extended Test SY01 -- Environment (CPU Load Impact){NC}")
    print(f"{W}{'='*72}{NC}")
    proc = start_server("./server", SAFE_SOCKET_PATH)
    time.sleep(0.2)

    # Baseline
    base_rtts = []
    for _ in range(20):
        r = send_ipc(SAFE_SOCKET_PATH, "SYS", "baseline_msg")
        if r["response_ms"] > 0: base_rtts.append(r["response_ms"])
        time.sleep(0.01)
    base_avg = round(sum(base_rtts)/len(base_rtts), 2) if base_rtts else -1
    print(f"  Baseline avg RTT (idle)      : {base_avg} ms  "
          f"(min {min(base_rtts):.2f}  max {max(base_rtts):.2f})")

    # Under CPU load
    stop_flag = threading.Event()
    def burn():
        while not stop_flag.is_set():
            _ = sum(i*i for i in range(10000))
    workers = [threading.Thread(target=burn, daemon=True) for _ in range(4)]
    for w in workers: w.start()
    time.sleep(0.15)

    load_rtts = []
    for _ in range(20):
        r = send_ipc(SAFE_SOCKET_PATH, "SYS", "loaded_msg")
        if r["response_ms"] > 0: load_rtts.append(r["response_ms"])
        time.sleep(0.01)
    stop_flag.set()

    load_avg   = round(sum(load_rtts)/len(load_rtts), 2) if load_rtts else -1
    drift_ms   = round(load_avg - base_avg, 2)
    drift_pct  = round((drift_ms / base_avg) * 100, 1) if base_avg > 0 else 0
    alive      = is_alive(SAFE_SOCKET_PATH)
    print(f"  Under CPU load avg RTT       : {load_avg} ms  "
          f"(min {min(load_rtts):.2f}  max {max(load_rtts):.2f})")
    print(f"  Latency drift under load     : +{drift_ms} ms  ({drift_pct}% increase)")
    print(f"  Server survived              : {'Yes' if alive else 'No'}")
    verdict = "PASS" if alive else "FAIL"
    print(f"  Verdict                      : {G if verdict=='PASS' else R}{verdict}{NC}")
    proc.terminate()
    return {
        "baseline_avg_ms": base_avg,
        "baseline_min_ms": round(min(base_rtts),2) if base_rtts else -1,
        "baseline_max_ms": round(max(base_rtts),2) if base_rtts else -1,
        "loaded_avg_ms":   load_avg,
        "loaded_min_ms":   round(min(load_rtts),2) if load_rtts else -1,
        "loaded_max_ms":   round(max(load_rtts),2) if load_rtts else -1,
        "drift_ms":        drift_ms, "drift_pct": drift_pct,
        "server_survived": alive, "verdict": verdict,
    }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    for b in ["./server", "./server_vuln"]:
        if not os.path.exists(b):
            print(f"{R}ERROR: '{b}' not found -- compile first.{NC}")
            return

    safe_results = run_tests("Safe Server",       SAFE_SOCKET_PATH, "./server",      SAFE_TESTS)
    vuln_results = run_tests("Vulnerable Server", VULN_SOCKET_PATH, "./server_vuln", VULN_TESTS)
    all_results  = safe_results + vuln_results

    integration = run_integration_test()
    load        = run_load_test(100)
    error_cond  = run_error_condition_test()
    environment = run_environment_test()

    total     = len(all_results)
    passes    = sum(1 for r in all_results if r["verdict"] == "PASS")
    overflows = sum(1 for r in all_results if r["verdict"] == "OVERFLOW")
    fails     = sum(1 for r in all_results if r["verdict"] == "FAIL")
    crashes   = sum(1 for r in all_results if r["server_after"] == "Crashed")
    safe_rtt  = [r["response_ms"] for r in safe_results  if r["response_ms"] > 0]
    vuln_rtt  = [r["response_ms"] for r in vuln_results
                 if r["response_ms"] > 0 and r["overflow_bytes"] == 0]

    print(f"\n{W}{'='*72}{NC}")
    print(f"{W} Summary{NC}")
    print(f"{W}{'='*72}{NC}")
    print(f"  Core tests            : {total}")
    print(f"  {G}PASS                  : {passes}{NC}")
    print(f"  {M}OVERFLOW (exploit OK) : {overflows}{NC}")
    print(f"  {R}FAIL                  : {fails}{NC}")
    print(f"  Server crashes        : {crashes}")
    if safe_rtt:
        print(f"  Safe avg RTT          : {sum(safe_rtt)/len(safe_rtt):.2f} ms  "
              f"(min {min(safe_rtt):.2f}  max {max(safe_rtt):.2f})")
    if vuln_rtt:
        print(f"  Vuln avg RTT          : {sum(vuln_rtt)/len(vuln_rtt):.2f} ms  "
              f"(min {min(vuln_rtt):.2f}  max {max(vuln_rtt):.2f})")
    print(f"\n  Extended test results:")
    print(f"    I01 Integration     : {G if integration['verdict']=='PASS' else R}"
          f"{integration['verdict']}{NC}")
    print(f"    L01 Load (100 msg)  : {G if load['verdict']=='PASS' else R}"
          f"{load['verdict']}{NC}  -- {load['throughput']} msg/s  avg {load['avg_rtt']} ms")
    print(f"    ER01 Error Cond     : {G if error_cond['verdict']=='PASS' else R}"
          f"{error_cond['verdict']}{NC}")
    print(f"    SY01 Environment    : {G if environment['verdict']=='PASS' else R}"
          f"{environment['verdict']}{NC}  -- drift +{environment['drift_ms']} ms "
          f"({environment['drift_pct']}% under CPU load)")

    output = {"core_tests": all_results, "integration": integration,
              "load": load, "error": error_cond, "environment": environment}
    with open(RESULTS_JSON, "w") as f:
        json.dump(output, f, indent=2)

    with open(RESULTS_TXT, "w") as f:
        hdr = "ID    Server               Category         PL   OF   RTT ms  After       Return Addr                Verdict\n"
        f.write(hdr + "-"*len(hdr) + "\n")
        for r in all_results:
            f.write("%-5s %-20s %-16s %4d %4d %7.1f  %-10s %-26s %s\n" % (
                r['id'], r['server'], r['category'],
                r['payload_bytes'], r['overflow_bytes'], r['response_ms'],
                r['server_after'], r['return_addr'], r['verdict']))
        f.write("\nCore: %d  PASS %d  OVERFLOW %d  FAIL %d\n" % (total, passes, overflows, fails))
        f.write("Load: %d msgs  %s msg/s  avg %s ms\n" % (load['messages'], load['throughput'], load['avg_rtt']))
        f.write("Env:  baseline %s ms  loaded %s ms  drift +%s ms\n" % (
            environment['baseline_avg_ms'], environment['loaded_avg_ms'], environment['drift_ms']))

    print("\033[92mSaved:\033[0m %s  %s\n" % (RESULTS_JSON, RESULTS_TXT))

if __name__ == "__main__":
    main()
