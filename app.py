from flask import Flask, render_template, request, redirect, url_for
from hashlib import sha256
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/{}"

def calculate_sha256(file_bytes):
    return sha256(file_bytes).hexdigest()

def query_virustotal(file_hash):
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(VT_URL.format(file_hash), headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "reputation": data["data"]["attributes"].get("reputation", 0),
            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
        }
    elif response.status_code == 404:
        return {"message": "Hash not found on VirusTotal"}
    else:
        return {"message": f"VirusTotal error: {response.status_code}"}

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None

    if request.method == 'POST':
        file = request.files['file']
        if file:
            contents = file.read()
            file_hash = calculate_sha256(contents)
            vt_data = query_virustotal(file_hash)

            result = {
                "filename": file.filename,
                "hash": file_hash,
                "virustotal": vt_data
            }

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
