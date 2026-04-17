# task3_forensics.py
# Malware Analysis and Digital Forensics Tool

import os
import hashlib
import shutil
from PIL import Image, ExifTags

# ---------------------------------------
# Create Quarantine Folder
# ---------------------------------------
quarantine_folder = "QUARANTINE_VAULT"

if not os.path.exists(quarantine_folder):
    os.mkdir(quarantine_folder)

# ---------------------------------------
# Known Malicious File Hashes
# ---------------------------------------
known_bad_hashes = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd38b0f1e4f4b6d8e2f"
]

# ---------------------------------------
# Generate SHA-256 Hash Safely
# ---------------------------------------
def generate_hash(file_path):

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except:
        return None


# ---------------------------------------
# Convert GPS Values to Decimal
# ---------------------------------------
def convert_gps(value):

    degrees = value[0][0] / value[0][1]
    minutes = value[1][0] / value[1][1]
    seconds = value[2][0] / value[2][1]

    decimal = degrees + (minutes / 60) + (seconds / 3600)

    return decimal


# ---------------------------------------
# Extract EXIF Metadata
# ---------------------------------------
def extract_metadata(file_path):

    try:
        image = Image.open(file_path)

        exif_data = image._getexif()

        if exif_data is None:
            print("\nNo EXIF metadata found.")
            return

        print("\nEXIF Metadata:")

        gps_info = {}

        for tag_id, value in exif_data.items():

            tag = ExifTags.TAGS.get(tag_id, tag_id)

            if tag == "GPSInfo":

                for key in value.keys():
                    gps_tag = ExifTags.GPSTAGS.get(key, key)
                    gps_info[gps_tag] = value[key]

            else:
                print(tag, ":", value)

        # GPS Coordinates
        if gps_info:

            print("\nGPS Coordinates:")

            latitude = convert_gps(gps_info["GPSLatitude"])
            longitude = convert_gps(gps_info["GPSLongitude"])

            if gps_info["GPSLatitudeRef"] == "S":
                latitude = -latitude

            if gps_info["GPSLongitudeRef"] == "W":
                longitude = -longitude

            print("Latitude :", latitude)
            print("Longitude:", longitude)

        else:
            print("No GPS coordinates found.")

    except:
        print("\nFile is not an image or metadata unavailable.")


# ---------------------------------------
# Move Malicious File to Quarantine
# ---------------------------------------
def move_to_quarantine(file_path):

    file_name = os.path.basename(file_path)

    destination = os.path.join(quarantine_folder, file_name)

    shutil.move(file_path, destination)

    print("\nThreat detected.")
    print("File moved to QUARANTINE_VAULT")


# ---------------------------------------
# Main Scan Function
# ---------------------------------------
def scan_file():

    print("=== Malware Analysis Tool ===")

    file_path = input("Enter suspicious file path: ").strip()

    if not os.path.exists(file_path):
        print("File not found.")
        return

    print("\nScanning file safely...")

    file_hash = generate_hash(file_path)

    if file_hash is None:
        print("Unable to read file.")
        return

    print("\nSHA-256 Hash:")
    print(file_hash)

    # Signature Checking
    if file_hash in known_bad_hashes:
        move_to_quarantine(file_path)

    else:
        print("\nNo known malicious signature found.")

    # Forensic Extraction
    extract_metadata(file_path)


# ---------------------------------------
# Run Program
# ---------------------------------------
scan_file()