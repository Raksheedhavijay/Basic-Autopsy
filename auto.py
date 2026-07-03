import os
import psutil
from datetime import datetime

def get_drives():

    print("\n==============================")
    print("AVAILABLE DRIVES IN SYSTEM")
    print("==============================\n")

    drives = psutil.disk_partitions()
    drive_list = []
    for i, drive in enumerate(drives):
        print(f"{i+1}. Drive : {drive.device}")
        print(f"   File System : {drive.fstype}")
        print(f"   Mount Point : {drive.mountpoint}")
        print()
        drive_list.append(drive.device)
    return drive_list

def check_removable_devices():

    print("\n==============================")
    print("USB / SD CARD DETECTION")
    print("==============================\n")

    drives = psutil.disk_partitions()
    found = False
    for drive in drives:
        if 'removable' in drive.opts.lower():
            print("Removable Device Found")
            print("Drive :", drive.device)
            print("Type  :", drive.fstype)
            print()
            found = True
    if not found:
        print("No Pendrive or SD Card Inserted\n")

def analyze_drive(path):

    print("\n===================================")
    print("STARTING DRIVE ANALYSIS")
    print("===================================\n")

    total_files = 0
    total_folders = 0
    total_size = 0
    for root, dirs, files in os.walk(path):
        total_folders += len(dirs)
        for file in files:
            try:
                file_path = os.path.join(root, file)
                size = os.path.getsize(file_path)
                created_time = os.path.getctime(file_path)
                modified_time = os.path.getmtime(file_path)
                created_time = datetime.fromtimestamp(created_time)
                modified_time = datetime.fromtimestamp(modified_time)

                print("--------------------------------------------------")
                print("FILE NAME      :", file)
                print("FILE LOCATION  :", file_path)
                print("FILE SIZE      :", size, "bytes")
                print("CREATED TIME   :", created_time)
                print("MODIFIED TIME  :", modified_time)

                total_files += 1
                total_size += size
            except Exception as e:
                pass

    print("\n===================================")
    print("DRIVE ANALYSIS COMPLETED")
    print("===================================")

    print("TOTAL FILES   :", total_files)
    print("TOTAL FOLDERS :", total_folders)
    print("TOTAL SIZE    :", total_size, "bytes")

print("\n========================================================")
print("   PROJECT : MINI AUTOPSY FORENSIC ANALYZER TOOL")
print("   Forensic Integrity : Evidence Source is READ-ONLY")
print("========================================================")

check_removable_devices()
drives = get_drives()

print("OPTIONS:")
print("  [1-N] Analyze a drive")
print("  R     Recover deleted files from a drive")
print("  Q     Quit")

action = input("\nEnter choice : ").strip().upper()

if action == 'Q':
    print("Exiting.")
elif action == 'R':
    from recover import recover_from_image
    for i, d in enumerate(drives):
        print(f"{i+1}. {d}")
    rchoice   = int(input("\nSelect Drive To Recover From : "))
    source    = drives[rchoice - 1]
    case_name = input("Enter case name (e.g. CASE-001) : ").strip() or "FORENSIC_CASE"
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recovered_files")
    recover_from_image(source, output_dir, case_name)
else:
    selected_drive = drives[int(action) - 1]
    print("\nSelected Drive :", selected_drive)
    analyze_drive(selected_drive)