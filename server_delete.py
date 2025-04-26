import os
import signal
import psutil

def kill_server():
    try:
        # Find all Python processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Check if this is our server process
                if proc.info['name'] == 'python.exe' and len(proc.info['cmdline']) > 1:
                    if 'server.py' in proc.info['cmdline'][1]:
                        print(f"Found server process with PID: {proc.info['pid']}")
                        # Terminate the process
                        os.kill(proc.info['pid'], signal.SIGTERM)
                        print("Server process terminated successfully")
                        return
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        print("No running server process found")
    except Exception as e:
        print(f"Error terminating server: {e}")

if __name__ == "__main__":
    kill_server() 