import re
import random
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import argparse

# ==========================================
# CONFIGURATION
# ==========================================

DEFAULT_COMMON_PASSWORD_FILE = "10-million-password-list-top-1000000.txt"

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit

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

def criteriaCheck(password: str) -> Dict[str, bool]:
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

def getStrengthValue(criteriaResults: Dict[str, bool]) -> str:
    """Maps total met criteria to a string of descriptive password strength level"""
    return PASSWORD_STRENGTH_VALUES[sum(criteriaResults.values())]

def getFeedback(criteriaResults: Dict[str, bool]) -> Tuple[List[str], List[str]]:
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

def commonlyUsedCheck(password: str, filename: str = DEFAULT_COMMON_PASSWORD_FILE) -> Optional[bool]:
    """Streams through a common password file to check if given password matches"""
    try:
        path = Path(filename)
        
        # 1. Verify it exists and is a real file (not a directory)
        if not path.is_file():
            print(f"\nError: The password list file '{filename}' was not found.")
            print("Warning: Will run script without common check\n")
            return None
        
        # 2. Enforce specific file type (.txt only)
        if path.suffix.lower() != ".txt":
            print(f"\nError: '{filename}' must be a .txt file.")
            return None
        
        # 3. Size validation guard (Resource Exhaustion protection)
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            print(f"\nError: File size exceeds the maximum allowed limit (50MB).")
            return None
        
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip() == password:
                    return True
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# ==========================================
# ORCHESTRATION
# ==========================================

def printResults(strength: str, criteriaFeedback: List[str], securityFeedback: List[str], isCommon: Optional[bool]) -> None:
    """Formats and displays evaluation results and security recommendations"""
    print("Password Strength: " + strength)
    for c in criteriaFeedback:
        print(" - " + c)
        
    if isCommon is True:
        print("\nYour password is among the most commonly used and could be easily cracked.")
        print("For your protection, please update it to something more secure!")
    elif isCommon is False:
        print("\nYour password is not in the Seclist top password list being used here.")
   
    print("\nSecurity Recommendations:")
    for s in securityFeedback:
        print(" - " + s)

def isPasswordStrong(password: str, filename: str = DEFAULT_COMMON_PASSWORD_FILE) -> None:
    """Validates input constraints and orchestrates workflow"""
    if not password or password.isspace():
            print("Invalid Password")
            return
    
    criteriaResults = criteriaCheck(password)
    strength = getStrengthValue(criteriaResults)
    criteriaFeedback, strengthFeedback = getFeedback(criteriaResults)
    isCommon = commonlyUsedCheck(password, filename)

    printResults(strength, criteriaFeedback, strengthFeedback, isCommon)

# ==========================================
# ARGUMENT PARSING AND MAIN FUNCTION
# ==========================================

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check password strength.")
    parser.add_argument(
        "--wordlist", 
        default=DEFAULT_COMMON_PASSWORD_FILE, 
        help="Path to custom common password .txt file"
    )
    return parser.parse_args()

def main() -> None:
    args = parse_arguments()
    
    password = input("Enter Password: ")
    isPasswordStrong(password, filename=args.wordlist)

if __name__ == '__main__':
    main()