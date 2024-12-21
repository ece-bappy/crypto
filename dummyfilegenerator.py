import os

def generate_dummy_file(file_name, size_in_mb):
    """Generate a dummy file with the specified size."""
    size_in_bytes = size_in_mb * 1024 * 1024
    with open(file_name, 'wb') as f:
        f.write(os.urandom(size_in_bytes))

# Example usage
generate_dummy_file("1GB.txt", 1024)  # Generates a 5 MB file named dummy_file.txt
