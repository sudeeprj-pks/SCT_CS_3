#!/usr/bin/env python3
"""
Password strength assessor CLI for local use.
Usage: python assess_password.py
Prompts you (hidden) for a password and prints a detailed assessment.
"""

import re
from math import log2
import getpass
import json
import argparse

COMMON_PATTERNS = [
    "password","123456","12345678","qwerty","abc123","letmein","admin","welcome","iloveyou"
]
SPECIAL_CHARS_RE = re.compile(r"[!\"#$%&'()*+,\-./:;<=>?@\[\]^_`{|}~]")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * log2(p)
    return entropy * len(s)

def assess_password(pw: str):
    reasons = []
    score = 0
    max_score = 8

    length = len(pw)
    # length scoring
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        reasons.append("Password is shorter than 8 characters (use 12+ for good security).")

    # character classes
    if re.search(r"[A-Z]", pw):
        score += 1
    else:
        reasons.append("No uppercase letters detected.")

    if re.search(r"[a-z]", pw):
        score += 1
    else:
        reasons.append("No lowercase letters detected.")

    if re.search(r"[0-9]", pw):
        score += 1
    else:
        reasons.append("No digits detected.")

    if SPECIAL_CHARS_RE.search(pw):
        score += 1
    else:
        reasons.append("No special characters detected (e.g. !, @, #, $).")

    entropy_bits = shannon_entropy(pw)
    if entropy_bits < 28:
        reasons.append(f"Low estimated entropy ({entropy_bits:.1f} bits). Try using longer and more varied characters.")
        if score > 2:
            score = max(0, score - 1)
    elif entropy_bits > 60:
        score = min(max_score, score + 1)

    low = pw.lower()
    for pat in COMMON_PATTERNS:
        if pat in low:
            reasons.append(f"Contains common pattern: '{pat}'. Avoid dictionary words and common sequences.")
            score = max(0, score - 2)
            break

    if re.search(r"(.)\1\1", pw):  # three repeated chars
        reasons.append("Contains repeated characters (like 'aaa' or '111'). Avoid long repeats.")
        score = max(0, score - 1)
    if re.search(r"012|123|234|345|456|567|678|789|890|qwe|wer|asd|sdf", low):
        reasons.append("Contains sequential characters (e.g., '123' or 'qwe'). Avoid obvious sequences.")
        score = max(0, score - 1)

    score = max(0, min(score, max_score))

    pct = (score / max_score) * 100
    if pct >= 88:
        rating = "Very Strong"
    elif pct >= 70:
        rating = "Strong"
    elif pct >= 50:
        rating = "Moderate"
    elif pct >= 30:
        rating = "Weak"
    else:
        rating = "Very Weak"

    suggestions = []
    if length < 12:
        suggestions.append("Increase the password length to 12 or more characters.")
    if not re.search(r"[A-Z]", pw):
        suggestions.append("Add at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", pw):
        suggestions.append("Add lowercase letters (a-z).")
    if not re.search(r"[0-9]", pw):
        suggestions.append("Add digits (0-9).")
    if not SPECIAL_CHARS_RE.search(pw):
        suggestions.append("Add special characters (e.g., ! @ # $ %).")
    suggestions.append("Avoid dictionary words, predictable substitutions (e.g., 'P@ssw0rd'), and common sequences.")
    suggestions.append("Consider using a passphrase (multiple unrelated words) or a password manager to generate/store long random passwords.")

    return {
        "length": length,
        "entropy_bits": round(entropy_bits, 1),
        "raw_score": score,
        "max_score": max_score,
        "percent": round(pct, 1),
        "rating": rating,
        "reasons": reasons,
        "suggestions": suggestions
    }

def pretty_print(result, show_json=False):
    if show_json:
        print(json.dumps(result, indent=2))
        return
    print(f"Rating: {result['rating']} ({result['percent']}%)")
    print(f"Score: {result['raw_score']}/{result['max_score']}  Entropy: {result['entropy_bits']} bits  Length: {result['length']}")
    if result['reasons']:
        print("\nIssues:")
        for r in result['reasons']:
            print("  -", r)
    print("\nSuggestions:")
    for s in result['suggestions']:
        print("  -", s)

def main():
    parser = argparse.ArgumentParser(description="Password strength assessor (local).")
    parser.add_argument("--show-json", action="store_true", help="Print full result as JSON")
    parser.add_argument("--password", "-p", help="Provide password on command line (NOT RECOMMENDED)")
    args = parser.parse_args()

    if args.password:
        pw = args.password
    else:
        try:
            pw = getpass.getpass("Enter password to assess (input hidden): ")
        except Exception:
            pw = input("Enter password to assess: ")

    if not pw:
        print("No password entered. Exiting.")
        return

    res = assess_password(pw)
    pretty_print(res, show_json=args.show_json)

if __name__ == "__main__":
    main()
