import base64
from rich.console import Console
from rich.panel import Panel

console = Console()

# === Hash Detection and Links ===

HASH_TYPES = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
    "SHA-512": 128,
}

def detect_hash(text):
    """Detect possible hash type based on length and characters."""
    for hash_type, length in HASH_TYPES.items():
        if len(text) == length and all(c in "0123456789abcdefABCDEF" for c in text):
            return hash_type
    return None

def provide_hash_cracking_links(hash_value):
    """Provide links to online hash-cracking tools."""
    console.print("\n[bold yellow]You can try cracking this hash at the following online tools:[/bold yellow]")
    
    urls = [
        f"https://crackstation.net/",
        f"https://hashes.com/en/decrypt/hash/{hash_value}",
        f"https://md5hashing.net/hash/{hash_value}",
        f"https://www.nitrxgen.net/md5db/{hash_value}",
        f"https://www.md5online.org/md5-decrypt.html",
    ]
    
    for i, url in enumerate(urls, 1):
        console.print(f"[green]{i}. {url}[/green]")

# === Base Encoding Detection and Decoding ===

def detect_base_encoding(text):
    """Detect base encoding type."""
    try:
        base64.b64decode(text, validate=True)
        return "Base64"
    except Exception:
        pass

    try:
        base64.b32decode(text, validate=True)
        return "Base32"
    except Exception:
        pass

    try:
        base64.b85decode(text)
        return "Base85"
    except Exception:
        pass

    return None

def decode_base(text, encoding_type):
    """Decode text based on detected base encoding."""
    try:
        if encoding_type == "Base64":
            return base64.b64decode(text).decode("utf-8")
        elif encoding_type == "Base32":
            return base64.b32decode(text).decode("utf-8")
        elif encoding_type == "Base85":
            return base64.b85decode(text).decode("utf-8")
    except Exception as e:
        return f"Error decoding: {e}"
    return "Unsupported base encoding"

# === Classical Ciphers ===

def caesar_cipher_decrypt(text, shift):
    """Decrypt Caesar cipher with a given shift."""
    decrypted = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            decrypted += chr((ord(char) - shift_base - shift) % 26 + shift_base)
        else:
            decrypted += char
    return decrypted

def vigenere_decrypt(text, key):
    """Decrypt Vigenère cipher with a key."""
    decrypted = ""
    key = [ord(char) - 65 for char in key.upper()]
    key_index = 0
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            decrypted += chr((ord(char) - shift_base - key[key_index]) % 26 + shift_base)
            key_index = (key_index + 1) % len(key)
        else:
            decrypted += char
    return decrypted

def atbash_cipher_decrypt(text):
    """Decrypt Atbash cipher."""
    decrypted = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                decrypted += chr(90 - (ord(char) - 65))
            else:
                decrypted += chr(122 - (ord(char) - 97))
        else:
            decrypted += char
    return decrypted

# === Binary and Hex Decryption ===

def binary_decrypt(text):
    """Convert binary text to plain text."""
    try:
        binary_values = text.split()
        ascii_string = "".join([chr(int(b, 2)) for b in binary_values])
        return ascii_string
    except Exception as e:
        return f"Error decoding binary: {e}"

def hex_decrypt(text):
    """Convert hexadecimal text to plain text."""
    try:
        return bytes.fromhex(text).decode("utf-8")
    except Exception as e:
        return f"Error decoding hex: {e}"

# === Main Tool ===

def main():
    console.print(
        Panel.fit(
            "[bold magenta]TH3CRYPT0LI0N[/bold magenta]\n"
            "[bold cyan]Made by [yellow]N0tAR3aLLI0N[/yellow][/bold cyan]\n\n"
            "[bold green]Tool Features:[/bold green]\n"
            "[bold white]- Detect and classify hash types[/bold white]\n"
            "[bold white]- Decode Base64, Base32, and Base85 encoded strings[/bold white]\n"
            "[bold white]- Crack binary and hexadecimal encodings[/bold white]\n"
            "[bold white]- Decrypt Classical Ciphers (Caesar, Atbash, Vigenère)[/bold white]",
            title="[bold blue]Welcome to TH3CRYPT0LI0N[/bold blue]",
            border_style="bold magenta",
        )
    )
    console.print("[bold green]1.[/bold green] Detect a hash type")
    console.print("[bold green]2.[/bold green] Identify and decrypt a cipher")
    choice = input("Choose an option (1/2): ")

    if choice == "1":
        hash_value = input("Enter the hash value: ").strip()
        hash_type = detect_hash(hash_value)
        if hash_type:
            console.print(f"\n[bold green]Detected Hash Type: {hash_type}[/bold green]")
            provide_hash_cracking_links(hash_value)
        else:
            console.print("\n[bold red]Unable to detect the hash type. Make sure the hash is valid.[/bold red]")

    elif choice == "2":
        text = input("Enter the text to analyze: ").strip()

        # Detect and decode base encoding
        base_type = detect_base_encoding(text)
        if base_type:
            console.print(f"[green]Detected {base_type} encoding![/green]")
            decoded = decode_base(text, base_type)
            console.print(f"[bold green]Decoded text:[/bold green] {decoded}")
            return

        # Attempt Binary and Hex decoding
        if all(c in "01 " for c in text):
            console.print("[yellow]Detected potential binary encoding.[/yellow]")
            decoded_binary = binary_decrypt(text)
            console.print(f"[bold green]Decoded binary text:[/bold green] {decoded_binary}")
            return

        if all(c in "0123456789abcdefABCDEF" for c in text.replace(" ", "")):
            console.print("[yellow]Detected potential hexadecimal encoding.[/yellow]")
            decoded_hex = hex_decrypt(text)
            console.print(f"[bold green]Decoded hex text:[/bold green] {decoded_hex}")
            return

        # Attempt Classical Ciphers
        console.print("[yellow]Attempting Caesar cipher decryption...[/yellow]")
        for shift in range(26):
            possible = caesar_cipher_decrypt(text, shift)
            console.print(f"Shift {shift}: {possible}")

        console.print("[yellow]Attempting Atbash cipher decryption...[/yellow]")
        decrypted_atbash = atbash_cipher_decrypt(text)
        console.print(f"[bold green]Decrypted with Atbash:[/bold green] {decrypted_atbash}")

        console.print("[yellow]Attempting Vigenère cipher decryption...[/yellow]")
        key = input("Enter Vigenère key: ").strip()
        decrypted_vigenere = vigenere_decrypt(text, key)
        console.print(f"[bold green]Decrypted with Vigenère:[/bold green] {decrypted_vigenere}")

    else:
        console.print("[red]Invalid option selected. Please try again.[/red]")

while(1):

    if __name__ == "__main__":
         main()
