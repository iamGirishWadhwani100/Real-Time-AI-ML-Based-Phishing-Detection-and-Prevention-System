from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import whois
import hashlib
from PIL import Image, ExifTags
from stegano import lsb
import io
import ssl
import socket
from OpenSSL import crypto
from datetime import datetime
import email
from email.header import decode_header
import asyncio

# --- Configuration ---
# IMPORTANT: Replace with your actual VirusTotal API Key
VIRUSTOTAL_API_KEY = "766decf12ad230dbab2b906fda620a76295f2ad4f675473615ff47d5a1ac7672"
VT_URL_API = "https://www.virustotal.com/api/v3/urls"
VT_FILE_API = "https://www.virustotal.com/api/v3/files"
HIBP_API_URL = "https://api.pwnedpasswords.com/range"

# --- FastAPI App Initialization ---
app = FastAPI(
    title="Aetherium Shield API",
    description="Backend services for the Aetherium Shield Security Toolkit."
)

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# --- Pydantic Models ---
class TextPayload(BaseModel):
    text: str

class PasswordPayload(BaseModel):
    password: str

# --- API Endpoints ---
tools_router = FastAPI()

# --- Existing Tools ---

@tools_router.get("/scan-url/")
async def scan_url(url: str):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    payload = {"url": url}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Submit the URL for analysis
            post_response = await client.post(VT_URL_API, headers=headers, data=payload)
            post_response.raise_for_status()
            analysis_id = post_response.json()["data"]["id"]
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            
            # Step 2: Poll for the analysis report with a timeout
            max_polls = 12
            poll_interval = 5  # seconds
            for _ in range(max_polls):
                await asyncio.sleep(poll_interval)  # Wait before checking again
                get_response = await client.get(report_url, headers=headers)
                get_response.raise_for_status()
                result = get_response.json()
                if result['data']['attributes']['status'] == 'completed':
                    return result  # Success, return the completed report
            
            # If the loop finishes without a 'completed' status, the scan timed out
            raise HTTPException(status_code=408, detail="URL scan timed out. The analysis is taking too long. Please try again later.")

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@tools_router.get("/check-domain/")
async def check_domain(url: str):
    def run_whois(domain):
        # This synchronous function will be run in a separate thread
        return whois.whois(domain)
    try:
        loop = asyncio.get_event_loop()
        # Run the blocking whois call in an executor to prevent freezing the server
        domain_info = await loop.run_in_executor(None, run_whois, url)

        if not domain_info or not domain_info.registrar:
            raise ValueError("Could not retrieve WHOIS data. The domain may not exist or the data is private.")
        
        # whois can return a list of dates, so we handle that case
        creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
        expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date

        return { 
            "domain": url, 
            "registrar": domain_info.registrar, 
            "creation_date": creation_date, 
            "expiration_date": expiration_date 
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@tools_router.post("/analyze-content/")
async def analyze_content(payload: TextPayload):
    text = payload.text.lower()
    keywords = [
        'verify your account', 'password', 'urgent', 'account suspended', 'security alert', 'login', 'username', 
        'credit card', 'confirm your identity', 'immediate action required', 'winner', 'congratulations', 'free', 'prize', 'invoice', 'payment'
    ]
    found = list(set([kw for kw in keywords if kw in text]))
    return { "keyword_count": len(found), "suspicious_keywords_found": found }

@tools_router.post("/hash/")
async def generate_hash(algorithm: str = Form(...), text: str = Form(None), file: UploadFile = File(None)):
    if not text and not file:
        raise HTTPException(status_code=400, detail="Provide text or a file.")
    hasher = hashlib.new(algorithm.lower())
    if file:
        while chunk := await file.read(8192): hasher.update(chunk)
    else:
        hasher.update(text.encode())
    return {"algorithm": algorithm, "hash": hasher.hexdigest()}

@tools_router.post("/steganography/hide/")
async def steganography_hide(file: UploadFile = File(...), message: str = Form(...)):
    if not file.content_type.startswith("image/png"):
        raise HTTPException(status_code=400, detail="Please upload a PNG.")
    try:
        secret_image = lsb.hide(io.BytesIO(await file.read()), message)
        buffer = io.BytesIO()
        secret_image.save(buffer, "PNG")
        buffer.seek(0)
        return StreamingResponse(buffer, media_type="image/png")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to hide message: {e}")

@tools_router.post("/steganography/reveal/")
async def steganography_reveal(file: UploadFile = File(...)):
    if not file.content_type.startswith("image/png"):
        raise HTTPException(status_code=400, detail="Please upload a PNG.")
    try:
        message = lsb.reveal(io.BytesIO(await file.read()))
        if not message:
            raise HTTPException(status_code=404, detail="No hidden message found.")
        return {"message": message}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reveal message: {e}")

@tools_router.get("/analyze-ssl/")
async def analyze_ssl(url: str):
    domain = url.split('//')[-1].split('/')[0].split(':')[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
                subject = dict(cert.get_subject().get_components())
                issuer = dict(cert.get_issuer().get_components())
                return {
                    "domain": domain,
                    "subject": {k.decode(): v.decode() for k, v in subject.items()},
                    "issuer": {k.decode(): v.decode() for k, v in issuer.items()},
                    "valid_from": datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ'),
                    "valid_to": datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ'),
                    "has_expired": cert.has_expired()
                }
    except socket.timeout:
        raise HTTPException(status_code=408, detail=f"Connection to {domain} timed out.")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Could not resolve hostname: {domain}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not retrieve SSL certificate: {e}")

# --- New Tools ---

@tools_router.post("/analyze-email-headers/")
async def analyze_email_headers(payload: TextPayload):
    try:
        headers = email.message_from_string(payload.text)
        auth_results = headers.get("Authentication-Results", "Not found")
        spf, dkim, dmarc = "Not found", "Not found", "Not found"
        if "spf=" in auth_results: spf = auth_results.split("spf=")[1].split(" ")[0]
        if "dkim=" in auth_results: dkim = auth_results.split("dkim=")[1].split(" ")[0]
        if "dmarc=" in auth_results: dmarc = auth_results.split("dmarc=")[1].split(" ")[0]
        
        return {
            "from": headers.get("From"),
            "subject": headers.get("Subject"),
            "to": headers.get("To"),
            "date": headers.get("Date"),
            "spf": spf, "dkim": dkim, "dmarc": dmarc
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse headers: {e}")

@tools_router.post("/scan-file/")
async def scan_file(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{VT_FILE_API}/{file_hash}", headers=headers)
            if response.status_code == 404:
                # If not found, we would normally upload it. For this tool, we'll just report 'not found'.
                 raise HTTPException(status_code=404, detail="File hash not found in VirusTotal database. Upload functionality not implemented in this version.")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@tools_router.post("/check-password-leak/")
async def check_password_leak(payload: PasswordPayload):
    try:
        sha1_hash = hashlib.sha1(payload.password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{HIBP_API_URL}/{prefix}")
            response.raise_for_status()
        
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return {"pwned": True, "count": int(count)}
        return {"pwned": False, "count": 0}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@tools_router.post("/view-exif/")
async def view_exif(file: UploadFile = File(...)):
    try:
        img = Image.open(file.file)
        exif_data = img._getexif()
        if not exif_data:
            raise HTTPException(status_code=404, detail="No EXIF data found in this image.")
        
        decoded_exif = {ExifTags.TAGS.get(tag_id, tag_id): value for tag_id, value in exif_data.items()}
        # Clean up non-serializable bytes
        for key, val in decoded_exif.items():
            if isinstance(val, bytes):
                decoded_exif[key] = val.decode(errors='ignore')

        return decoded_exif
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read EXIF data: {e}")

app.include_router(tools_router, prefix="/tools")

