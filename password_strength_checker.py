import re
import random
from pathlib import Path

# ==========================================
# CONFIGURATION
# ==========================================

DEFAULT_COMMON_PASSWORD_FILE = Path("10-million-password-list-top-1000000.txt")

PASSWORD_STRENGTH_VALUES = {
    0 : "Very Weak",
    1 : "Very Weak",
    2 : "Weak",
    3 : "Good",
    4 : "Very Good",
    5 : "Strong"
}

SECURITY_RECOMMENDATIONS = [
    "Though the recommended minimum length is 8, NIST recommends 15 for optimal security",
    "Update passwords periodically, especially for sensitive accounts",
    "Never use the same password for multiple accounts or services",
    "Avoid the use of common, simple, and predictable passwords",
    "Check if password was previously exposed in data breach - such as Have I Been Pwned",
    "Use Multi-Factor Authentication when given the option",
    "Do not use personal information in the password",
    "Use a reliable password manager to generate and securely store unique/complex passwords for multiple accounts",
    "Opt for a passphrase composed of multiple random words to ensure strong security and simple recall",
    "Avoid predictable character substitutions - such as '3' for 'E' or '@' for 'A'"
]

# ==========================================
# VALIDATION AND EVALUATION
# ==========================================

def criteriaCheck(password):
    """Evaluates password against length, case, digit, and special character"""
    hasMinLength = len(password) >= 15
    hasLowercase = re.search(r"[a-z]", password) is not None
    hasUppercase = re.search(r"[A-Z]", password) is not None
    hasDigit = re.search(r"\d", password) is not None
    #" !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
    specialChars = re.compile(' |!|"|#|\$|%|&|\'|\(|\)|\*|\+|,|-|\.|\/|:|;|<|=|>|\?|@|\[|\\|]|\^|_|`|{|\||}|~')
    hasSpecial = specialChars.search(password) is not None
    
    return {
        "hasMinLength": hasMinLength,
        "hasLowercase": hasLowercase,
        "hasUppercase": hasUppercase,
        "hasDigit": hasDigit,
        "hasSpecial": hasSpecial
    }

def getStrengthValue(criteriaResults):
    """Maps total met criteria to a string of descriptive password strength level"""
    return PASSWORD_STRENGTH_VALUES[sum(criteriaResults.values())]

def getFeedback(criteriaResults):
    """Generates specific criteria improvements and recommendations based on evaluation results"""
    criteriaFeedback = []
    strengthFeedback = []
    
    if not criteriaResults["hasMinLength"]:
        criteriaFeedback.append("Must be at least 15 characters")
        strengthFeedback.append("NIST recommends at least 15 characters long to enhance security (NIST SP800-63B)")
    if not criteriaResults["hasLowercase"]:
        criteriaFeedback.append("Must have at least 1 lowercase letter")
    if not criteriaResults["hasUppercase"]:
        criteriaFeedback.append("Must have at least 1 uppercase letter")
    if not criteriaResults["hasDigit"]:
        criteriaFeedback.append("Must have at least 1 number")
    if not criteriaResults["hasSpecial"]:
        criteriaFeedback.append("Must have at least 1 special character")
        strengthFeedback.append("OWASP recommends using these characters (between double quotes): \" !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~\"")
    
    if len(strengthFeedback) < 3:
        newfeedback = random.sample(SECURITY_RECOMMENDATIONS, 3 - len(strengthFeedback))
        for n in newfeedback:
            strengthFeedback.append(n)
        
    return criteriaFeedback, strengthFeedback

def commonlyUsedCheck(password, filename=DEFAULT_COMMON_PASSWORD_FILE):
    """Streams through a common password file to check if given password matches"""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip() == password:
                    return True
        return False
    except FileNotFoundError:
        print(f"Error: The password list file '{filename}' was not found.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

# ==========================================
# ORCHESTRATION
# ==========================================

def printResults(strength, criteriaFeedback, strengthFeedback, isCommon):
    """Formats and displays evaluation results and security recommendations"""
    print("Password Strength: " + strength)
    for c in criteriaFeedback:
        print(" - " + c)
        
    if isCommon:
        print("\nYour password is among the most commonly used and could be easily cracked.")
        print("For your protection, please update it to something more secure!")
    else:
        print("\nYour password is not in the Seclist top password list being used here.")
        
    print("\nSecurity Recommendations:")
    for s in strengthFeedback:
        print(" - " + s)

def isPasswordStrong(password):
    """Validates input constraints and orchestrates workflow"""
    if not password or password.isspace():
            print("Invalid Password")
            return
    
    criteriaResults = criteriaCheck(password)
    strength = getStrengthValue(criteriaResults)
    criteriaFeedback, strengthFeedback = getFeedback(criteriaResults)
    isCommon = commonlyUsedCheck(password)

    printResults(strength, criteriaFeedback, strengthFeedback, isCommon)

# ==========================================
# MAIN FUNCTION
# ==========================================

def main():
    password = input("Enter Password: ")
    isPasswordStrong(password)

if __name__ == '__main__':
    main()