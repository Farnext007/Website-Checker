from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from openai import OpenAI
import os
from dotenv import load_dotenv
import re
import base64
import urllib.parse

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Load environment variables
load_dotenv()
openai_api_key = os.getenv("OPENAI_API_KEY")
screenshotapi_key = os.getenv("SCREENSHOTAPI_KEY")

if not openai_api_key:
    print("Error: OPENAI_API_KEY not found in .env file")

try:
    client = OpenAI(api_key=openai_api_key)
except Exception as e:
    print(f"Error initializing OpenAI client: {e}")

def is_valid_url(url):
    """Validate if the input is a proper URL with http:// or https://."""
    regex = re.compile(
        r'^https?://'  # Must start with http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def capture_screenshot_with_screenshotapi(url):
    """Capture a screenshot using ScreenshotAPI.net."""
    try:
        print(f"Capturing screenshot with ScreenshotAPI.net for {url}")
        
        if not screenshotapi_key or screenshotapi_key == "your_screenshotapi_key_here":
            return {"screenshot": None, "error": "ScreenshotAPI.net key not configured"}
        
        # Updated ScreenshotAPI.net endpoint (as indicated in the error)
        api_url = "https://api.screenshotapi.net/screenshot"
        
        # Parameters for the API request
        params = {
            'token': screenshotapi_key,  # Using 'token' parameter instead of header
            'url': url,
            'width': 1280,
            'height': 720,
            'full_page': 'false',
            'fresh': 'true'  # Don't use cached screenshot
        }
        
        print(f"Making request to ScreenshotAPI.net for: {url}")
        
        # Make the API request
        response = requests.get(api_url, params=params, timeout=30)
        
        print(f"ScreenshotAPI.net response status: {response.status_code}")
        
        if response.status_code == 200:
            # Check if the response is actually an image
            content_type = response.headers.get('content-type', '')
            if 'image' in content_type:
                # Convert the image to base64
                screenshot_data = base64.b64encode(response.content).decode('utf-8')
                print("Screenshot captured successfully with ScreenshotAPI.net")
                return {"screenshot": screenshot_data, "error": None}
            else:
                # Try to parse error message if not an image
                error_text = response.text[:200]
                error_msg = f"ScreenshotAPI.net returned non-image content: {error_text}"
                print(error_msg)
                return {"screenshot": None, "error": error_msg}
        else:
            error_msg = f"ScreenshotAPI.net error: {response.status_code} - {response.text[:200]}"
            print(error_msg)
            return {"screenshot": None, "error": error_msg}
            
    except requests.RequestException as e:
        error_msg = f"ScreenshotAPI.net request failed: {str(e)}"
        print(error_msg)
        return {"screenshot": None, "error": error_msg}
    except Exception as e:
        error_msg = f"Unexpected error with ScreenshotAPI.net: {str(e)}"
        print(error_msg)
        return {"screenshot": None, "error": error_msg}

# Alternative screenshot method using a different service
def capture_screenshot_fallback(url):
    """Fallback screenshot method for when ScreenshotAPI fails."""
    try:
        # Using a simple alternative - this may not work for all sites
        # but can serve as a backup
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        import tempfile
        
        print(f"Trying fallback screenshot method for: {url}")
        
        # Configure Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1280,720")
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        
        # Take screenshot
        screenshot_data = driver.get_screenshot_as_base64()
        driver.quit()
        
        print("Fallback screenshot captured successfully")
        return {"screenshot": screenshot_data, "error": None}
        
    except Exception as e:
        error_msg = f"Fallback screenshot also failed: {str(e)}"
        print(error_msg)
        return {"screenshot": None, "error": error_msg}

def check_webpage_content(url):
    """Check if the specific webpage is real using Open AI API."""
    try:
        # Check for full URL with scheme
        if not url or not url.strip().startswith(('http://', 'https://')):
            return {"result": "Please enter the full URL starting with http:// or https://", "screenshot": None, "error": None}

        # Validate URL format
        if not is_valid_url(url):
            return {"result": "Invalid URL format", "screenshot": None, "error": None}

        # Prepare prompt for Open AI
        prompt = f"""
        Analyze the following webpage URL to determine if the specific page is legitimate (real) and safe.
        URL: {url}
        
        Consider factors such as:
        - URL structure (e.g., misspellings, unusual subdomains or paths)
        - Domain reputation (e.g., well-known sites like udemy.com are generally safe)
        - Signs of phishing or scam pages

        Respond with exactly one of these two options:
        - "The webpage URL is real and seems safe" if the page is legitimate and safe.
        - "The webpage URL is not real" if the page shows signs of being fake, suspicious, or is inaccessible.
        """
        
        # Call Open AI API
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert in website security and legitimacy analysis. Only respond with one of the two specified options."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=50
        )
        
        result = response.choices[0].message.content.strip()
        screenshot_data = None
        screenshot_error = None
        
        # Check if the result indicates a real and safe website
        if "real and seems safe" in result.lower():
            screenshot_result = capture_screenshot_with_screenshotapi(url)
            screenshot_data = screenshot_result.get("screenshot")
            screenshot_error = screenshot_result.get("error")
            
            # If ScreenshotAPI fails, try fallback
            if not screenshot_data:
                screenshot_result = capture_screenshot_fallback(url)
                screenshot_data = screenshot_result.get("screenshot")
                screenshot_error = screenshot_result.get("error")
        
        return {
            "result": result, 
            "screenshot": screenshot_data, 
            "error": screenshot_error
        }
    
    except Exception as e:
        return {
            "result": f"Error analyzing webpage: {str(e)}", 
            "screenshot": None, 
            "error": None
        }

@app.route('/check-website', methods=['POST'])
def check_website():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({
            'result': 'Please provide a URL', 
            'screenshot': None, 
            'error': None
        }), 400
    
    result = check_webpage_content(url)
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    print("Server ready on port 5001")
    print(f"ScreenshotAPI.net key: {'Configured' if screenshotapi_key and screenshotapi_key != 'your_screenshotapi_key_here' else 'Not configured'}")
    app.run(debug=True, port=5001)