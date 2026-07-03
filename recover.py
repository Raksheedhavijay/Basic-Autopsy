import os
import csv
import pytsk3
from datetime import datetime
from integrity import begin_case, end_case

SUPPORTED_EXT = {
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'txt', 'csv', 'xml', 'json', 'html',
    'mp3', 'mp4', 'wav', 'avi', 'mkv', 'mov',
    'zip', 'rar', 'gz', 'tar', '7z',
    'py', 'js', 'c', 'cpp', 'java', 'sh',
    'exe', 'dll', 'so', 'db'
}

def ts_to_str(ts):
    try:
        if ts and ts > 0:
            return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        pass
    return "Unknown"
def safe_name(name_info):
    try:
        return name_info.name.decode('utf-8', errors='replace') if name_info else "unknown"
    except Exception:
        return "unknown"
class ReadOnlyImg(pytsk3.Img_Info):
    """
    Opens the evidence source strictly read-only via O_RDONLY file descriptor.
    pytsk3 internally uses this path — passing it through Img_Info(url)
    already opens read-only on Linux block devices. This subclass makes
    the intent explicit and documented for chain-of-custody purposes.
    """
    def __init__(self, path):
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
        super().__init__(path)

def recover_from_image(image_path, output_dir, case_name="FORENSIC_CASE"):
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "recovery_report.csv")

    print(f"\n{'='*55}")
    print(f"  PROJECT : MINI AUTOPSY FORENSIC RECOVERY TOOL")
    print(f"{'='*55}")
    print(f"  Case    : {case_name}")
    print(f"  Source  : {image_path}")
    print(f"  Output  : {output_dir}")
    print(f"{'='*55}")
    pre_hash = begin_case(image_path, output_dir, case_name)

    recovered_files = []
    recovered_count = 0
    try:
        img = ReadOnlyImg(image_path)
    except PermissionError:
        print("[!] Permission denied. Run with sudo.")
        return
    except Exception as e:
        print(f"[!] Cannot open source: {e}")
        return
    try:
        part_table = pytsk3.Volume_Info(img)
        partitions = [
            (p.start, p.desc.decode(errors='replace'))
            for p in part_table if p.len > 2048
        ]
    except Exception:
        partitions = [(0, "raw")]

    for start_sector, desc in partitions:
        print(f"\n[*] Partition : {desc}  (sector offset: {start_sector})")
        try:
            fs = pytsk3.FS_Info(img) if start_sector == 0 and desc == "raw" \
                 else pytsk3.FS_Info(img, offset=start_sector * 512)
        except Exception as e:
            print(f"    [-] Cannot read filesystem: {e}")
            continue

        def walk_dir(inode_num, path="/"):
            try:
                directory = fs.open_dir(inode=inode_num)
            except Exception:
                return

            for entry in directory:
                name = safe_name(entry.info.name)
                if name in (".", "..") or not entry.info.name:
                    continue

                is_deleted = bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                is_dir     = (entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR)

                try:
                    meta = entry.info.meta
                except Exception:
                    meta = None
                if is_dir and not is_deleted and meta:
                    walk_dir(meta.addr, os.path.join(path, name))
                    continue

                if not is_deleted:
                    continue
                ext        = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
                size       = meta.size       if meta else 0
                created    = ts_to_str(meta.crtime if meta else 0)
                modified   = ts_to_str(meta.mtime  if meta else 0)
                inode_addr = meta.addr       if meta else "N/A"
                full_path  = os.path.join(path, name)

                print(f"\n  [DELETED] {full_path}")
                print(f"  ├─ Name         : {name}")
                print(f"  ├─ Original Path: {full_path}")
                print(f"  ├─ Size         : {size} bytes")
                print(f"  ├─ Created      : {created}")
                print(f"  ├─ Modified     : {modified}")
                print(f"  └─ Inode        : {inode_addr}")

                saved_path = "N/A (metadata only)"

                # Save file content (read-only extraction, writes only to output_dir)
                try:
                    if meta and size > 0 and ext in SUPPORTED_EXT:
                        safe_fname = name.replace('/', '_').replace('\\', '_')
                        out_file   = os.path.join(output_dir, f"inode{inode_addr}_{safe_fname}")
                        if not os.path.exists(out_file):
                            file_obj = fs.open_meta(inode=inode_addr)
                            data     = file_obj.read_random(0, size)
                            with open(out_file, 'wb') as f:
                                f.write(data)
                            saved_path = out_file
                            recovered_count += 1
                            print(f"     → Saved to  : {out_file}")
                except Exception:
                    pass

                recovered_files.append({
                    "File Name"    : name,
                    "Original Path": full_path,
                    "Size (bytes)" : size,
                    "Created Date" : created,
                    "Modified Date": modified,
                    "Inode"        : inode_addr,
                    "Extension"    : ext,
                    "Saved To"     : saved_path,
                })

        walk_dir(fs.info.root_inum)
    fields = ["File Name", "Original Path", "Size (bytes)",
              "Created Date", "Modified Date", "Inode", "Extension", "Saved To"]
    with open(report_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(recovered_files)
    end_case(image_path, output_dir, pre_hash, recovered_count, report_path)

    print(f"{'='*55}")
    print(f"  RECOVERY COMPLETE")
    print(f"  Deleted entries found : {len(recovered_files)}")
    print(f"  Files recovered       : {recovered_count}")
    print(f"  Report                : {report_path}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    import psutil

    print("\n" + "="*55)
    print("  PROJECT : MINI AUTOPSY FORENSIC RECOVERY TOOL")
    print("="*55 + "\n")

    drives = [d for d in psutil.disk_partitions(all=True)
              if not d.device.startswith('/dev/loop')]

    for i, d in enumerate(drives):
        print(f"  {i+1}. {d.device}  [{d.fstype}]  →  {d.mountpoint}")
    print(f"  {len(drives)+1}. Enter custom path / disk image (.img / .dd)\n")

    choice = int(input("Select option : "))
    source = drives[choice - 1].device if choice <= len(drives) \
             else input("Enter full path : ").strip()

    case_name  = input("Enter case name (e.g. CASE-001) : ").strip() or "FORENSIC_CASE"
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recovered_files")

    recover_from_image(source, output_dir, case_name)
