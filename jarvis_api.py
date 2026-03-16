import json
import urllib.request
import urllib.error

print("===================================================")
print(" 🧠 J.A.R.V.I.S. LIVE API ADVISORY ENGINE ONLINE")
print("===================================================")

# 1. INSERT YOUR API KEY HERE
# You can get a free Gemini API key from: [https://aistudio.google.com/](https://aistudio.google.com/)
API_KEY = "AIzaSyAv7yg-jMU6mFFTMtUMj2EhHQJiv3L0Wcc"

def get_jarvis_advisory(user_prompt):
    """
    Sends the user's prompt to the LLM API to get a dynamic tactical advisory decision.
    """
    if API_KEY == "YOUR_GEMINI_API_KEY_HERE":
        return "<span class='text-red-muted'>[-] CRITICAL ERROR: API Key missing. Please insert your Gemini API Key in the script.</span>"

    # Gemini 1.5 Flash API Endpoint
    url = f"[https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=](https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=){API_KEY}"
    
    # The System Prompt tells the AI exactly how to behave and format its output
    system_prompt = """
    You are J.A.R.V.I.S., an elite autonomous cybersecurity assistant and SOC analyst.
    The Operator will ask you for help or tell you they are stuck on a hacking challenge, CTF, or forensic task.
    
    YOUR Directives:
    1. Act as a tactical mentor. Give brilliant advisory decisions.
    2. Suggest specific commands (like for nmap, privilege escalation, web bypasses, etc).
    3. FORMAT YOUR RESPONSE FOR A CYBERPUNK TERMINAL using HTML.
    
    Use these HTML tags to color-code your response:
    - <span class='text-yellow-muted font-bold'>[TACTICAL ADVISORY]</span> for headers.
    - <span class='text-cyan-muted'>text</span> for general highlighting.
    - <span class='text-green-muted'>text</span> for successful or safe commands.
    - <span class='text-red-muted'>text</span> for critical warnings.
    - Use <b> and <code> tags for terminal commands.
    - Use <br><br> for line breaks instead of standard newlines.
    """

    # Construct the API Payload
    payload = {
        "contents": [{"parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]}
    }

    # Make the HTTP Request
    req = urllib.request.Request(
        url, 
        data=json.dumps(payload).encode('utf-8'), 
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            response_data = json.loads(response.read().decode())
            # Extract the AI's generated text
            ai_reply = response_data['candidates'][0]['content']['parts'][0]['text']
            return ai_reply
            
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode()
        return f"<span class='text-red-muted'>[-] API HTTP ERROR {e.code}: {error_msg}</span>"
    except Exception as e:
        return f"<span class='text-red-muted'>[-] API CONNECTION ERROR: {str(e)}</span>"

# 2. INTERACTIVE TESTING CONSOLE
print(" Type a hacking scenario you are stuck on.")
print(" Type 'exit' to quit.")
print("="*50)

while True:
    user_input = input("\n[Operator]> ")
    if user_input.lower() == 'exit':
        print("Shutting down API connection...")
        break
    
    if user_input.strip() == "":
        continue

    print("\n[*] Transmitting telemetry to Global AI API...")
    
    # Get the dynamic response from the API
    dynamic_response = get_jarvis_advisory(user_input)
    
    print(f"\n[Jarvis Brain Output (Formatted HTML)] ->\n\n{dynamic_response}\n")