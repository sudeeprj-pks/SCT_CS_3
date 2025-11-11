 Password Strength Assessor (CLI Tool)

A simple Python-based **password strength checker** that analyzes passwords for:
- Length  
- Use of uppercase & lowercase letters  
- Numbers  
- Special characters  
- Entropy (randomness)  
- Common patterns and sequences  

It provides a **score**, **rating**, and **suggestions** to improve your password security.

---

Features
 Rates password strength as **Very Weak → Very Strong**  
 Detects common patterns like `"password"`, `"123456"`, `"qwerty"`, etc.  
 Calculates **Shannon entropy** for randomness estimation  
 Gives detailed feedback and improvement suggestions  
 Works **locally on your system** (no passwords sent anywhere)  
 Supports **JSON output** for integration with other tools  

---

 Requirements
Make sure you have **Python 3.8+** and **Git** installed.

To check:
```bash
python3 --version
git --version
