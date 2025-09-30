# Password-Strength-Checker
A Python tool that evaluates the password strength using best practices outlined by NIST SP 800-63B and OWASP. It analyses password length, character complexity, and checks against a large list of known compromosed passwords (SecList) to provide feedback for creating stronger, safer passwords.

## Features
- Enforces NIST-recommended minimum length (15 characters)
- Checks presence of lowercase, uppercase, numbers, and special characters recommended by OWASP
- Checks passwords against a common-password blacklist (SecList Top 10M)
- Returns clear security feedback to the user
- Includes unit tests to validate logic

## Password Criteria 
| Criteria                 | Description                                                              |
| ------------------------ | ------------------------------------------------------------------------ |
| **Minimum Length**       | 15 characters (as recommended by NIST)                                   |
| **Character Complexity** | At least one of each: lowercase, uppercase, digit, and special character |
| **Blacklist Check**      | Password is not among top 10M commonly used passwords (via SecList)      |

💡 Feedback is provided for each missing criteria.

## Resources
- [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Special Characters](https://owasp.org/www-community/password-special-characters)
- [OWASP Authenticaiton Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet)
- [SecLists Common Password Lists](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
