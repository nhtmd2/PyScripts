import hashlib
import os
from tkinter import Tk, filedialog

def calculate_hash(file_path, hash_type):
    """
    Calculate the hash of a file based on the specified hash type.

    :param file_path: Path to the file.
    :param hash_type: Type of hash to calculate ('md5', 'sha1', 'sha256').
    :return: Hash value as a hex string.
    """
    hash_function = getattr(hashlib, hash_type)()

    try:
        with open(file_path, 'rb') as file:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: file.read(4096), b""):
                hash_function.update(chunk)
        return hash_function.hexdigest()
    except FileNotFoundError:
        return f"Error: File '{file_path}' not found."
    except Exception as e:
        return f"Error: {str(e)}"

def get_file_hashes(file_path):
    """
    Get MD5, SHA-1, and SHA-256 hashes of a file.

    :param file_path: Path to the file.
    :return: Dictionary containing hash types and their values.
    """
    hash_types = ['md5', 'sha1', 'sha256']
    hashes = {}
    for hash_type in hash_types:
        hashes[hash_type] = calculate_hash(file_path, hash_type)
    return hashes

def main():
    print("File Hash Calculator")
    print("====================")

    # Open file dialog to select a file
    Tk().withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("All Files", "*.*")])

    if not file_path:
        print("No file selected. Exiting.")
        return

    print(f"\nSelected File: {file_path}")

    print("\nCalculating hashes...")
    hashes = get_file_hashes(file_path)

    print("\nFile Hashes:")
    for hash_type, hash_value in hashes.items():
        print(f"{hash_type.upper()}: {hash_value}")

if __name__ == "__main__":
    main()
