import os
import shutil
from datetime import datetime

def organize_audit_outputs():
    # Folder name formatted with timestamp: audit_YYYY-MM-DD_HH-MM-SS
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    target_folder = f"audit_{timestamp}"

    os.makedirs(target_folder, exist_ok=True)
    print(f"[*] Created output directory: {target_folder}")

    # Move raw prowler output folder if exists
    if os.path.exists("output"):
        shutil.move("output", os.path.join(target_folder, "prowler_raw_data"))
        print(f" -> Moved 'output/' to '{target_folder}/prowler_raw_data'")

    # Move custom html report if exists
    if os.path.exists("custom_report.html"):
        shutil.move("custom_report.html", os.path.join(target_folder, "custom_report.html"))
        print(f" -> Moved 'custom_report.html' to '{target_folder}/custom_report.html'")

    print(f"\n[✓] Done! All audit files are preserved inside '{target_folder}/'")

if __name__ == "__main__":
    organize_audit_outputs()