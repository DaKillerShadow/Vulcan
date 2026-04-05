import subprocess
import time
import sys

def main():
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║     B U I L D  V U L N E R A B I L I T Y  S C A N N E R          ║")
    print("║                     L A U N C H  S E Q U E N C E                 ║")
    print("╚══════════════════════════════════════════════════════════════════╝\n")
    
    # STEP 1: Run the Backend Scanner
    print("[*] INITIATING BACKEND SCANNER...")
    try:
        # Replace with the exact name of your scanner script
        subprocess.run([sys.executable, "network_web_scanner_V2.py"], check=True)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[X] Scanner error: {e}")
        
    print("\n[*] SCAN COMPLETE. CSV DATA GENERATED.")
    time.sleep(2) # Brief pause for file system to save the CSV
    
    # STEP 2: Launch the AI Dashboard
    print("[*] CONNECTING TO AI DASHBOARD...")
    print("[*] Launching Streamlit interface in your browser...\n")
    try:
        subprocess.run(["streamlit", "run", "app.py"])
    except Exception as e:
        print(f"\n[X] Dashboard launch error: {e}")
        print("Make sure streamlit is installed (pip install streamlit)")

if __name__ == "__main__":
    main()

