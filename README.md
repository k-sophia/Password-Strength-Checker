# Password-Strength-Checker
A Python tool that evaluates password strength using best practices outlined by **NIST SP 800-63B** and **OWASP**. It analyzes password length, character complexity, and checks against a large list of known compromised passwords (SecLists) to provide actionable feedback for creating stronger, safer passwords.

## ⚡ Features

- **NIST Alignment:** Enforces NIST-recommended minimum length (15+ characters)
- **OWASP Complexity Check:** Verifies presence of lowercase, uppercase, digits, and special characters
- **Breached Password Blacklist:** Checks passwords against the top common password list via SecLists file
- **Actionable Feedback:** Delivers clear security feedback and recommendations for any missing criteria
- **Unit Tested:** Includes comprehensive test suites to validate logic

## 📋 Password Criteria 

| Criteria | Requirements / Standard |
|----------|-------------------------|
| **Minimum Length** | 15 characters (NIST SP 800-63B recommendation) |
| **Character Complexity** | At least one lowercase, uppercase, digit, and special character |
| **Blacklist Check** | Password must not appear in the common password blacklist |

💡 *Clear, individual feedback is provided for each unmet criterion.*

## 🚀 Usage & Setup

### Prerequisites
* Python 3.x

### Running the Checker
Execute the main script to check password strength:

```bash
python3 password_strength_checker.py
```

### Running Tests
To run the automated test suite and verify functionality:

```bash
python3 -m unittest test_cases.py
```

## 💻 Example Output

### Checker Example with Weak Password

```bash
$ python3 password_strength_checker.py 
Enter Password: passwordtest

Password Strength: Very Weak

Areas for Improvement:
 - Must be at least 15 characters
 - Must have at least 1 uppercase letter
 - Must have at least 1 number
 - Must have at least 1 special character

Your password is not in the Seclist top password list being used here.

Security Recommendations:
 - NIST recommends at least 15 characters long to enhance security (NIST SP800-63B)
 - OWASP recommends using these characters (between double quotes): " !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
 - Avoid predictable character substitutions - such as '3' for 'E' or '@' for 'A'
```

### Unit Test Example

```bash
$ python3 -m unittest test_cases.py 
............................
----------------------------------------------------------------------
Ran 28 tests in 0.922s

OK
```

## 📚 Resources
- [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Password Special Characters](https://owasp.org/www-community/password-special-characters)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet)
- [SecLists Common Password Lists](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
