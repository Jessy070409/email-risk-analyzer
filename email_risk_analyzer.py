import re

def analyze_email(email_text):
    risk_score = 0
    flags = []

    # 1. Check for urgent or threatening language
    urgent_keywords = [
        "urgent", "immediately", "action required", "account suspended",
        "verify now", "24 hours", "unauthorized", "limited time", "final notice"
    ]
    found_urgent = [word for word in urgent_keywords if word in email_text.lower()]
    if found_urgent:
        risk_score += 2
        flags.append(f"Urgent language detected: {', '.join(found_urgent)}")

    # 2. Check for sensitive data prompts
    sensitive_keywords = [
        "password", "ssn", "social security", "credit card", "bank account",
        "pin", "otp", "login credentials", "confirm your identity"
    ]
    found_sensitive = [word for word in sensitive_keywords if word in email_text.lower()]
    if found_sensitive:
        risk_score += 3
        flags.append(f"Requests sensitive information: {', '.join(found_sensitive)}")

    # 3. Check for links (URLs) and suspicious domains/IPs
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_text)
    if urls:
        risk_score += 1
        flags.append(f"Contains {len(urls)} link(s): {', '.join(urls)}")
        for url in urls:
            # Flag raw IP addresses or URL shorteners
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url) or any(s in url for s in ["bit.ly", "tinyurl", "t.co"]):
                risk_score += 2
                flags.append(f"High-risk or shortened URL detected: {url}")

    # Determine overall risk level
    if risk_score >= 5:
        risk_level = "HIGH RISK (Likely Phishing)"
    elif risk_score >= 2:
        risk_level = "MEDIUM RISK (Suspicious)"
    else:
        risk_level = "LOW RISK (Appears Safe)"

    return risk_level, risk_score, flags


def main():
    print("=== Email Risk Analyzer ===")
    print("Paste the email content below (press Enter twice when done):\n")
    
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    
    email_content = "\n".join(lines)

    if not email_content.strip():
        print("No email content provided.")
        return

    risk_level, score, flags = analyze_email(email_content)

    print("\n--- Scan Results ---")
    print(f"Status: {risk_level} (Score: {score})")
    if flags:
        print("Detected Issues:")
        for flag in flags:
            print(f" - {flag}")
    else:
        print("No obvious phishing indicators found.")


if __name__ == "__main__":
    main()
