import socket

def run(ip, port, service=None, banner=None):
    result = {
        "vulnerable": False,
        "details": ""
    }

    try:
        if banner and "vsftpd 2.3.4" in banner.lower():
            result["details"] = "vsFTPd 2.3.4 - Backdoor present (CVE-2011-2523)"

            s = socket.create_connection((ip, port), timeout=5)
            s.recv(1024)  
            s.sendall(b"USER test:)\r\n")
            resp = s.recv(1024).decode(errors='ignore')

            if "220" in resp or "421" in resp or not resp:
                result["vulnerable"] = True
                result["details"] += " | Active validation: backdoor response received"
            else:
                result["details"] += " | Active validation: backdoor not confirmed"

            s.close()
        else:
            result["vulnerable"] = False
            result["details"] = ""

    except Exception as e:
        result["vulnerable"] = False
        result["details"] = f"Active validation error: {e}"

    return result
