# create_url_dataset.py
import pandas as pd
import os

print("📁 Creating URL phishing dataset...")

# Legitimate URLs
legitimate_urls = [
    'https://www.google.com',
    'https://www.facebook.com',
    'https://www.amazon.com',
    'https://www.microsoft.com',
    'https://www.apple.com',
    'https://www.github.com',
    'https://www.stackoverflow.com',
    'https://www.wikipedia.org',
    'https://www.youtube.com',
    'https://www.twitter.com',
    'https://www.linkedin.com',
    'https://www.instagram.com',
    'https://www.netflix.com',
    'https://www.spotify.com',
    'https://www.paypal.com',
    'https://www.banking.com',
    'https://www.gmail.com',
    'https://www.outlook.com',
    'https://www.dropbox.com',
    'https://www.drive.google.com'
]

# Phishing URLs
phishing_urls = [
    'http://paypal-verify-account.ru/login',
    'http://secure-banking-xyz.com/update',
    'http://apple-id-verify.xyz/account',
    'http://facebook-login.net/security',
    'http://amazon-prime-verify.ru/update',
    'http://netflix-account-verify.com/login',
    'http://microsoft-verify.net/account',
    'http://instagram-followers.xyz/login',
    'http://google-verify.ru/security',
    'http://dropbox-share.xyz/file',
    'http://bankofamerica-verify.com/update',
    'http://wellsfargo-login.net/account',
    'http://chase-banking.ru/verify',
    'http://paypal-security.net/login',
    'http://apple-update.xyz/account',
    'http://amazon-claim.ru/gift',
    'http://facebook-security.net/verify',
    'http://instagram-verified.xyz/login',
    'http://linkedin-connect.ru/update',
    'http://whatsapp-verify.com/account'
]

# Create DataFrame
urls = legitimate_urls + phishing_urls
labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)

df = pd.DataFrame({
    'url': urls,
    'label': labels
})

# Save to file
os.makedirs('data/phishing', exist_ok=True)
df.to_csv('data/phishing/url_data.csv', index=False)

print(f"✅ Created dataset with {len(df)} URLs")
print(f"   - Legitimate: {len(legitimate_urls)}")
print(f"   - Phishing: {len(phishing_urls)}")
print("\n📁 Saved to: data/phishing/url_data.csv")