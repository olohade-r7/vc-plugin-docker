# Git Workflow - Simple Steps

How to create a branch, push code, and create a Pull Request.

---

## **Step 1: Check Current Status**

```bash
cd /Users/olohade/miniProject/scrapper
git status
```

This shows what files changed.

---

## **Step 2: Create a New Branch**

```bash
git checkout -b feature/fingerprinting-agent
```

Branch name: `feature/fingerprinting-agent` (you can change this)

---

## **Step 3: Add All Changes**

```bash
git add .
```

This stages all new and modified files.

---

## **Step 4: Commit Changes**

```bash
git commit -m "Add fingerprinting agent module with local and remote scanning"
```

You can change the message to describe your work.

---

## **Step 5: Push to GitHub**

```bash
git push origin feature/fingerprinting-agent
```

If this is first push, it might ask you to set upstream:
```bash
git push --set-upstream origin feature/fingerprinting-agent
```

---

## **Step 6: Create Pull Request on GitHub**

1. Go to your GitHub repository in browser
2. You'll see a banner: "Compare & pull request" - Click it
3. Fill in PR details:
   - **Title:** "Add Fingerprinting Agent Module"
   - **Description:** 
     ```
     ## What's New
     - Added fingerprinting agent for system & software detection
     - Supports local and remote (SSH) scanning
     - Generates JSON reports with evidence tracking
     - Organized code into web_scraper and fingerprinting_agent folders
     
     ## How to Test
     Local scan:
     ```bash
     cd fingerprinting_agent
     python main.py --local
     ```
     
     Remote scan (Docker):
     ```bash
     python main.py --remote localhost --user root --key ~/.ssh/id_rsa --port 2222
     ```
     
     ## Documentation
     - See fingerprinting_agent/README.md
     - See fingerprinting_agent/REMOTE_SETUP_GUIDE.md
     ```
4. Click "Create Pull Request"

---

## **Step 7: Get PR Link**

After creating PR, copy the URL from browser. It looks like:
```
https://github.com/YOUR_USERNAME/scrapper/pull/1
```

---

## **Step 8: Share with Mentor/Manager**

Send them:

**Email Template:**
```
Subject: Pull Request for Review - Fingerprinting Agent Module

Hi [Mentor Name],

I've completed the fingerprinting agent module. Please review my PR:

🔗 PR Link: https://github.com/YOUR_USERNAME/scrapper/pull/1

## What's Included:
✅ System & software fingerprinting (local + remote)
✅ SSH-based remote scanning
✅ Evidence-based reporting (JSON output)
✅ Complete documentation

## Testing Done:
- Local scan on macOS ✅
- Remote scan via Docker Ubuntu ✅
- Generated fingerprint reports ✅

Please let me know if you have any feedback!

Thanks,
[Your Name]
```

---

## **Common Git Commands**

### Check which branch you're on:
```bash
git branch
```

### See what changed:
```bash
git diff
```

### Go back to main branch:
```bash
git checkout main
```

### Update your branch with latest main:
```bash
git checkout main
git pull
git checkout feature/fingerprinting-agent
git merge main
```

---

## **If You Make More Changes After Creating PR**

```bash
# Make your changes, then:
git add .
git commit -m "Fix: description of fix"
git push origin feature/fingerprinting-agent
```

The PR will automatically update!

---

**That's it!** 🚀
