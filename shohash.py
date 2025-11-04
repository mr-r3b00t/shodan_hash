import requests
from urllib.parse import urlparse
import base64

def murmurhash3_x86_32(data, seed=0):
    """MurmurHash3 x86_32 implementation."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = (length // 4) * 4

    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xff) | ((data[i+1] & 0xff) << 8) | \
             ((data[i+2] & 0xff) << 16) | ((data[i+3] & 0xff) << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF  # ROTL32
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF  # ROTL32
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    k1 = 0
    remaining = length % 4
    if remaining == 3:
        k1 ^= (data[rounded_end + 2] & 0xff) << 16
    if remaining >= 2:
        k1 ^= (data[rounded_end + 1] & 0xff) << 8
    if remaining >= 1:
        k1 ^= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF  # ROTL32
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    return h1  # Signed 32-bit, but can be used as unsigned

def main():
    url = input("Enter URL (e.g., https://example.com): ").strip()
    if not url:
        print("Please enter a valid URL.")
        return

    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.hostname:
            raise ValueError("Invalid URL format.")
        
        favicon_url = f"{parsed_url.scheme}://{parsed_url.hostname}/favicon.ico"
        
        response = requests.get(favicon_url, verify=False, allow_redirects=True, timeout=10)
        response.raise_for_status()
        
        raw_data = response.content  # bytes
        encoded_data = base64.encodebytes(raw_data)  # MIME base64 with line breaks and trailing \n
        hash_value = murmurhash3_x86_32(encoded_data)
        
        # Convert to signed 32-bit for Shodan compatibility
        signed_hash = hash_value - (1 << 32) if hash_value & (1 << 31) else hash_value
        print(f"Shodan http.favicon.hash: {signed_hash}")
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
