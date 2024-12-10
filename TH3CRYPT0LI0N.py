#!/usr/bin/env python3
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

def detect_base64(text):
    """Detect Base64 encoding."""
    try:
        base64.b64decode(text, validate=True)
        return "Base64"
    except Exception:
        return None

def decode_base64(text):
    """Decode Base64 encoded text."""
    try:
        return base64.b64decode(text).decode("utf-8")
    except Exception as e:
        return f"Error decoding Base64: {e}"

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

def rot13_decrypt(text):
    """Decrypt ROT13 cipher."""
    return caesar_cipher_decrypt(text, 13)

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

def reverse_cipher_decrypt(text):
    """Decrypt Reverse Cipher."""
    return text[::-1]

def morse_code_decrypt(text):
    """Decrypt Morse Code."""
    MORSE_CODE_DICT = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '-----': '0', '/': ' '
    }
    try:
        return ''.join(MORSE_CODE_DICT[char] for char in text.split())
    except KeyError:
        return "Error decoding Morse Code."

def bacon_cipher_decrypt(text):
    """Decrypt Bacon's Cipher."""
    BACON_DICT = {
        "aaaaa": "A", "aaaab": "B", "aaaba": "C", "aaabb": "D", "aabaa": "E",
        "aabab": "F", "aabba": "G", "aabbb": "H", "abaaa": "I", "abaab": "J",
        "ababa": "K", "ababb": "L", "abbaa": "M", "abbab": "N", "abbba": "O",
        "abbbb": "P", "baaaa": "Q", "baaab": "R", "baaba": "S", "baabb": "T",
        "babaa": "U", "babab": "V", "babba": "W", "babbb": "X", "bbaaa": "Y",
        "bbaab": "Z"
    }
    try:
        return ''.join(BACON_DICT[char] for char in text.split())
    except KeyError:
        return "Error decoding Bacon's Cipher."

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
        return bytes.fromhex(text.replace(" ", "")).decode("utf-8")
    except Exception as e:
        return f"Error decoding hex: {e}"

# === Main Tool ===
def detect_bacon_or_hex(text):
    if all(c in "ABab " for c in text):
        return "Bacon"
    elif all(c in "0123456789abcdefABCDEF " for c in text):
        return "Hexadecimal"
    else:
        return None
def main():
    console.print(
        Panel.fit(
            "[bold magenta]TH3CRYPT0LI0N[/bold magenta]\n"
            "[bold cyan]Made by [yellow]N0tAR3aLLI0N[/yellow][/bold cyan]\n\n"
            "[bold green]Tool Features:[/bold green]\n"
            "- Detect and classify hash types\n"
            "- Decode Base64, Hexadecimal, and Binary encodings\n"
            "- Decrypt Classical Ciphers (Caesar, Atbash, Vigenère, ROT13, Morse, Reverse, Bacon)",
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
        
        # Base64 Detection
        if detect_base64(text):
            console.print("[green]Detected Base64 encoding![/green]")
            console.print(f"[bold green]Decoded text:[/bold green] {decode_base64(text)}")
            return

        # Binary Detection
        if all(c in "01 " for c in text):
            console.print("[yellow]Detected potential binary encoding.[/yellow]")
            console.print(f"[bold green]Decoded binary text:[/bold green] {binary_decrypt(text)}")
            return

        # Bacon vs Hexadecimal Detection
        bacon_or_hex = detect_bacon_or_hex(text)
        if bacon_or_hex == "Bacon":
            console.print("[yellow]Detected Bacon's Cipher encoding.[/yellow]")
            console.print(f"[bold green]Decrypted Bacon's Cipher text:[/bold green] {bacon_cipher_decrypt(text.lower())}")
            return
        elif bacon_or_hex == "Hexadecimal":
            console.print("[yellow]Detected potential hexadecimal encoding.[/yellow]")
            console.print(f"[bold green]Decoded hex text:[/bold green] {hex_decrypt(text)}")
            return

        # Classical Cipher Detection
        console.print("[yellow]Attempting Morse code decryption...[/yellow]")
        morse_result = morse_code_decrypt(text)
        if morse_result != "Error decoding Morse Code.":
            console.print(f"[bold green]Decrypted with Morse Code:[/bold green] {morse_result}")
            return
        
        console.print("[yellow]Attempting Caesar cipher decryption...[/yellow]")
        for shift in range(26):
            possible = caesar_cipher_decrypt(text, shift)
            console.print(f"Shift {shift}: {possible}")
        
        console.print("[yellow]Attempting ROT13 decryption...[/yellow]")
        console.print(f"[bold green]Decrypted with ROT13:[/bold green] {rot13_decrypt(text)}")

        console.print("[yellow]Attempting Atbash cipher decryption...[/yellow]")
        console.print(f"[bold green]Decrypted with Atbash:[/bold green] {atbash_cipher_decrypt(text)}")

        console.print("[yellow]Attempting Reverse cipher decryption...[/yellow]")
        console.print(f"[bold green]Decrypted with Reverse Cipher:[/bold green] {reverse_cipher_decrypt(text)}")

        console.print("[yellow]Attempting Bacon's cipher decryption...[/yellow]")
        bacon_result = bacon_cipher_decrypt(text)
        if bacon_result != "Error decoding Bacon's Cipher.":
            console.print(f"[bold green]Decrypted with Bacon Cipher:[/bold green] {bacon_result}")
        else:
            console.print("[red]Unable to identify or decode the cipher.[/red]")
    else:
        console.print("[red]Invalid option. Please choose either 1 or 2.[/red]")
while True:
    if __name__ == "__main__":
       main()
