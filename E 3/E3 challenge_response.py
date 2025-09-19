import hashlib
import os
import time

def generate_challenge():
    return os.urandom(16)  

def client_response(challenge, secret):
    combined = challenge + secret.encode()
    return hashlib.sha256(combined).hexdigest()

def server_verify(challenge, secret, response):
    expected = hashlib.sha256(challenge + secret.encode()).hexdigest()
    return expected == response

if __name__ == "__main__":
    secret = "mypassword123"  
    print("=== Challenge-Response Simulation ===")

    challenge = generate_challenge()
    print("Server sends challenge:", challenge.hex())

    response = client_response(challenge, secret)
    print("Client sends response:", response)

    if server_verify(challenge, secret, response):
        print("Server: Authentication successful!")
    else:
        print("Server: Authentication failed!")

    print("\n=== Replay Attack Simulation ===")
    print("Client re-sends previous response...")
    if server_verify(challenge, secret, response):
        print("Server: Authentication successful (VULNERABLE!)")
    else:
        print("Server: Authentication failed (Replay prevented!)")

    print("\n=== Using Fresh Challenge to Prevent Replay ===")
    new_challenge = generate_challenge()
    new_response = client_response(new_challenge, secret)
    if server_verify(new_challenge, secret, new_response):
        print("Server: Authentication successful with fresh challenge!")
