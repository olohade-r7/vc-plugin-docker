# Remote Scanning Setup Guide (Docker Ubuntu)

Quick guide to set up a remote Ubuntu machine for fingerprinting testing.

---

## **What This Does**
Creates a fake remote Ubuntu Linux machine on your Mac using Docker. This lets you test remote SSH scanning without needing a real remote server.

---

## **Prerequisites**
- Docker installed and running on your Mac
- SSH key generated (`~/.ssh/id_rsa`)

---

## **Step-by-Step Setup**

### **Step 1: Create Remote Ubuntu Container**
```bash
docker run -d --name remote-test -p 2222:22 rastasheep/ubuntu-sshd:18.04
```

**What this does:** 
- Downloads Ubuntu 18.04 with SSH server
- Runs it in background (`-d`)
- Maps port 2222 on Mac → port 22 in container
- Names it `remote-test`

---

### **Step 2: Test SSH Connection**
```bash
ssh -p 2222 root@localhost
```

- **Username:** `root`
- **Password:** `root`
- Type `yes` when asked about fingerprint
- Type `exit` to logout

---

### **Step 3: Add Your SSH Key**
```bash
cat ~/.ssh/id_rsa.pub | ssh -p 2222 root@localhost "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

- **Password:** `root` (last time!)
- This copies your public key to the container

---

### **Step 4: Test Key-Based Login**
```bash
ssh -p 2222 -i ~/.ssh/id_rsa root@localhost "echo 'Success!'"
```

Should print `Success!` without asking for password ✅

---

### **Step 5: Run Remote Fingerprinting Scan**
```bash
cd /Users/olohade/miniProject/scrapper/fingerprinting_agent
source ../venv/bin/activate
python main.py --remote localhost --user root --key ~/.ssh/id_rsa --port 2222
```

---

### **Step 6: View Results**
```bash
cat output/fingerprint_report.json
```

---

### **Step 7: Cleanup (When Done)**
```bash
# Stop container
docker stop remote-test

# Remove container
docker rm remote-test
```

---

## **Connection Details**

| Setting | Value |
|---------|-------|
| **Host** | `localhost` |
| **Port** | `2222` |
| **Username** | `root` |
| **Password** | `root` (not needed after Step 3) |
| **SSH Key** | `~/.ssh/id_rsa` |

---

## **Common Commands**

### Check if container is running:
```bash
docker ps | grep remote-test
```

### Restart container:
```bash
docker restart remote-test
```

### View container logs:
```bash
docker logs remote-test
```

### SSH into container manually:
```bash
ssh -p 2222 -i ~/.ssh/id_rsa root@localhost
```

---

## **What Gets Detected**

The remote scan detects:
- ✅ OS: Ubuntu 18.04
- ✅ Kernel version
- ✅ CPU information
- ✅ Installed software (Python, etc.)

All results saved to: `output/fingerprint_report.json`

---

## **Troubleshooting**

**Port already in use:**
```bash
# Use different port
docker run -d --name remote-test -p 2223:22 rastasheep/ubuntu-sshd:18.04
# Then use --port 2223 in scan command
```

**Permission denied:**
```bash
chmod 600 ~/.ssh/id_rsa
```

**Connection refused:**
```bash
# Check if container is running
docker ps | grep remote-test

# Restart if needed
docker restart remote-test
```

---

## **Real Remote Server Setup**

To scan an actual remote Linux/Ubuntu server:

1. Get server IP: `192.168.1.100`
2. Get username: `admin`
3. Copy SSH key: 
   ```bash
   ssh-copy-id -i ~/.ssh/id_rsa.pub admin@192.168.1.100
   ```
4. Run scan:
   ```bash
   python main.py --remote 192.168.1.100 --user admin --key ~/.ssh/id_rsa
   ```

---

**That's it!** 🚀
