import os
import random
import string

def generate_file(filename, size_bytes):
    chunk_size = 1024 
    total_written = 0

    with open(filename, 'w') as f:
        while total_written < size_bytes:
            to_write = min(chunk_size, size_bytes - total_written)
            data = ''.join(random.choices(string.ascii_letters + string.digits, k=to_write))
            f.write(data)
            total_written += to_write

sizes = [
    ("file_10KB.txt", 10 * 1024),        # 10 KB
    ("file_50KB.txt", 50 * 1024),        # 50 KB
    ("file_100KB.txt", 100 * 1024),      # 100 KB
    ("file_500KB.txt", 500 * 1024),      # 500 KB
    ("file_1MB.txt", 1 * 1024 * 1024),   # 1 MB
    ("file_5MB.txt", 5 * 1024 * 1024)    # 5 MB
]

for filename, size in sizes:
    print(f"Generating {filename} with size {size} bytes...")
    generate_file(filename, size)

print("All files generated.")
