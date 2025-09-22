import uvicorn
import httpx
import whois
import hashlib
import io
import ssl
import socket
import asyncio
from datetime import datetime

from fastapi import FastAPI, APIRouter, HTTPException, File, UploadFile, Form, Body
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, ExifTags
from stegano import lsb
from OpenSSL import crypto

# --- App Initialization ---
app = FastAPI(
    title="Aetherium Shield API",
    description="A multi-tool security analysis backend.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

tools_router = APIRouter()
VIRUSTOTAL_API_KEY = "766decf12ad230dbab2b906fda620a76295f2ad4f675473615ff47d5a1ac7672" # Stored on the backend for security

# --- Helper Functions ---
def get_domain_from_url(url: str) -> str:
    try:
        if "://" in url:
            url = url.split('://')[1]
        url = url.split('/')[0]
        return url
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL format.")
        
# --- API Endpoints ---

@tools_router.post("/scan-url/")
async def analyze_url(url: str = Form(...)):
    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key is not configured.")
    
    vt_url_scan = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            scan_payload = {"url": url}
            scan_response = await client.post(vt_url_scan, headers=headers, data=scan_payload)
            scan_response.raise_for_status()
            analysis_id = scan_response.json()["data"]["id"]

            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            
            # Poll for the report
            for _ in range(5): # Poll a few times
                await asyncio.sleep(3)
                report_response = await client.get(report_url, headers=headers)
                report_response.raise_for_status()
                report_data = report_response.json()
                if report_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                    return report_data
            
            return {"detail": "Scan submitted, but analysis is taking longer than expected. Please check VirusTotal directly."}


        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"VirusTotal API error: {e.response.text}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")

@tools_router.post("/check-domain/")
async def check_domain(domain: str = Form(...)):
    try:
        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if not creation_date:
            return {"error": "Could not retrieve creation date for this domain. It might be a new or protected domain."}
        
        # Handle cases where dates are returned as a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0] if expiration_date else None

        age_days = (datetime.now() - creation_date).days if creation_date else -1
        
        return {
            "domain_name": domain_info.domain_name,
            "registrar": domain_info.registrar,
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else "N/A",
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else "N/A",
            "age_days": age_days
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not fetch WHOIS data. The domain may be invalid, private, or unsupported. Error: {e}")

@tools_router.post("/analyze-content/")
async def analyze_content(text: str = Form(...)):
    flags = []
    text_lower = text.lower()
    if "urgent" in text_lower or "immediate" in text_lower or "action required" in text_lower:
        flags.append("Urgency Detected")
    if "verify your account" in text_lower or "update your details" in text_lower or "confirm your password" in text_lower:
        flags.append("Credential Phishing Keywords")
    if "account has been suspended" in text_lower or "unusual sign-in" in text_lower:
        flags.append("Threat/Fear Mongering Language")
    if "you have won" in text_lower or "congratulations" in text_lower:
        flags.append("Suspicious Prize/Lottery Language")
    
    return {"flags": flags if flags else ["No immediate red flags detected."], "word_count": len(text.split())}

@tools_router.post("/hash/")
async def generate_hash(text: str = Form(None), file: UploadFile = File(None), algorithm: str = Form(...)):
    if not text and not file:
        raise HTTPException(status_code=400, detail="Please provide either text or a file.")
    if text and file:
        raise HTTPException(status_code=400, detail="Please provide either text or a file, not both.")

    hasher = hashlib.new(algorithm)
    if text:
        hasher.update(text.encode())
    else:
        contents = await file.read()
        hasher.update(contents)
    
    return {"hash": hasher.hexdigest(), "algorithm": algorithm}

@tools_router.post("/steganography/hide/")
async def stego_hide(file: UploadFile = File(...), message: str = Form(...)):
    if not file.content_type == "image/png":
        raise HTTPException(status_code=400, detail="Please upload a PNG file.")
    
    contents = await file.read()
    try:
        secret_img = lsb.hide(io.BytesIO(contents), message)
        buffer = io.BytesIO()
        secret_img.save(buffer, format="PNG")
        buffer.seek(0)
        return StreamingResponse(buffer, media_type="image/png", headers={"Content-Disposition": "attachment; filename=stego_image.png"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to hide message: {e}")


@tools_router.post("/steganography/reveal/")
async def stego_reveal(file: UploadFile = File(...)):
    if not file.content_type == "image/png":
        raise HTTPException(status_code=400, detail="Please upload a PNG file.")
        
    contents = await file.read()
    try:
        message = lsb.reveal(io.BytesIO(contents))
        return {"message": message or "No hidden message found."}
    except Exception:
        return {"message": "No hidden message found or image is invalid."}

@tools_router.post("/analyze-certificate/")
async def analyze_certificate(domain: str = Form(...)):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert_der = s.getpeercert(True)
        
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
        
        issuer = dict(cert.get_issuer().get_components())
        subject = dict(cert.get_subject().get_components())
        
        return {
            "issuer": issuer.get(b'O', b'N/A').decode(),
            "subject": subject.get(b'CN', b'N/A').decode(),
            "serial_number": str(cert.get_serial_number()),
            "valid_from": datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d'),
            "valid_until": datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d'),
            "is_expired": cert.has_expired()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not retrieve SSL certificate. Error: {e}")

@tools_router.post("/scan-file/")
async def scan_file(file: UploadFile = File(...)):
    file_hash = hashlib.sha256(await file.read()).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(url, headers=headers)
            if response.status_code == 404:
                return {
                    "status": "not_found",
                    "detail": "This file is not in the VirusTotal database. This means it is not a known threat, but it has not been scanned before."
                }
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"VirusTotal API error: {e.response.text}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


@tools_router.post("/analyze-email-headers/")
async def analyze_email_headers(data: dict = Body(...)):
    text = data.get("text", "")
    headers = {}
    spf = dkim = dmarc = "Not Found"
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
        if line.lower().startswith("authentication-results"):
            if "spf=pass" in line.lower(): spf = "Pass"
            elif "spf=fail" in line.lower(): spf = "Fail"
            if "dkim=pass" in line.lower(): dkim = "Pass"
            elif "dkim=fail" in line.lower(): dkim = "Fail"
            if "dmarc=pass" in line.lower(): dmarc = "Pass"
            elif "dmarc=fail" in line.lower(): dmarc = "Fail"
    
    return {
        "from": headers.get("from", "N/A"),
        "subject": headers.get("subject", "N/A"),
        "date": headers.get("date", "N/A"),
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }

@tools_router.post("/check-password-leak/")
async def check_password_leak(data: dict = Body(...)):
    password = data.get("password", "")
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            hashes = (line.split(":") for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return {"pwned": True, "count": int(count)}
            return {"pwned": False, "count": 0}
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"HIBP API error: {e.response.text}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

@tools_router.post("/view-exif/")
async def view_exif(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        img = Image.open(io.BytesIO(contents))
        
        metadata = {
            "Filename": file.filename,
            "File Size (bytes)": len(contents),
            "Image Format": img.format,
            "Image Mode": img.mode,
            "Dimensions": f"{img.width}x{img.height}"
        }

        exif_data = img._getexif()
        if not exif_data:
            metadata["EXIF Status"] = "No EXIF metadata found in this image."
            return metadata
            
        exif = {ExifTags.TAGS[k]: v for k, v in exif_data.items() if k in ExifTags.TAGS}
        for key, val in exif.items():
            if isinstance(val, bytes):
                exif[key] = val.decode(errors='ignore')
        
        # Combine basic metadata with detailed EXIF data
        metadata.update(exif)
        return metadata

    except Exception:
        return {"message": "Could not process image. It may not have EXIF data or is not a supported format (like JPG)."}


# --- Mount Router ---
app.include_router(tools_router, prefix="/tools")

# --- Run App (for local development) ---
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

