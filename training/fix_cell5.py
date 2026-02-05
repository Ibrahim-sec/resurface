#@title 5️⃣ Login to Hugging Face (for model access)
from huggingface_hub import login, whoami

# Check if already logged in
try:
    user = whoami()
    print(f"✅ Already logged in as: {user['name']}")
except:
    print("🔑 Need Hugging Face token for Llama access")
    print("Get yours at: https://huggingface.co/settings/tokens")
    from getpass import getpass
    token = getpass("Enter HF token: ")
    login(token=token)
    print("✅ Logged in!")
