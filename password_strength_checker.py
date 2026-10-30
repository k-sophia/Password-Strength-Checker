import argparse
from enum import Enum
from pathlib import Path
import random
import re
import math
from typing import Dict, List, Optional, Tuple

# ==========================================
# CONFIGURATION
# ==========================================

DEFAULT_COMMON_PASSWORD_FILE = "10-million-password-list-top-1000000.txt"

SPECIAL_CHARS_PATTERN = re.compile(r'[ !"#\$%&\'()*+,\-./:;<=>?@\[\\\]^_`{|}~]')

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit

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
# CLASSES
# ==========================================

class StrengthTier(str, Enum):
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    GOOD = "Good"
    VERY_GOOD = "Very Good"
    STRONG = "Strong"
    
    @property
    def ansi_color(self) -> str:
        """Returns the ANSI color code corresponding to the strength tier."""
        color_map = {
            self.VERY_WEAK: "\033[91m",           # Red
            self.WEAK: "\033[38;5;208m",          # Orange
            self.GOOD: "\033[33m",                # Yellow
            self.VERY_GOOD: "\033[38;5;71m",      # Green
            self.STRONG: "\033[1m\033[32m",       # Light Green
        }
        return color_map[self]

    @classmethod
    def getStrengthValue(cls, criteriaResults: Dict[str, bool]) -> "StrengthTier":
        """Maps total met criteria directly to a StrengthTier enum."""
        score = sum(criteriaResults.values())
        
        tiers = [
            cls.VERY_WEAK,  # Score 0
            cls.VERY_WEAK,  # Score 1
            cls.WEAK,       # Score 2
            cls.GOOD,       # Score 3
            cls.VERY_GOOD,  # Score 4
            cls.STRONG,     # Score 5
        ]
        
        return tiers[score]

# ==========================================
# VALIDATION AND EVALUATION
# ==========================================

def criteriaCheck(password: str) -> Dict[str, bool]:
    """Evaluates password against length, case, digit, and special character"""
    hasMinLength = len(password) >= 15
    hasLowercase = re.search(r"[a-z]", password) is not None
    hasUppercase = re.search(r"[A-Z]", password) is not None
    hasDigit = re.search(r"\d", password) is not None
    hasSpecial = SPECIAL_CHARS_PATTERN.search(password) is not None
    
    return {
        "hasMinLength": hasMinLength,
        "hasLowercase": hasLowercase,
        "hasUppercase": hasUppercase,
        "hasDigit": hasDigit,
        "hasSpecial": hasSpecial
    }

def getFeedback(criteriaResults: Dict[str, bool]) -> Tuple[List[str], List[str]]:
    """Generates specific criteria improvements and recommendations based on evaluation results"""
    criteriaFeedback = []
    securityFeedback = []
    
    if not criteriaResults["hasMinLength"]:
        criteriaFeedback.append("Must be at least 15 characters")
        securityFeedback.append("NIST recommends at least 15 characters long to enhance security (NIST SP800-63B)")
    if not criteriaResults["hasLowercase"]:
        criteriaFeedback.append("Must have at least 1 lowercase letter")
    if not criteriaResults["hasUppercase"]:
        criteriaFeedback.append("Must have at least 1 uppercase letter")
    if not criteriaResults["hasDigit"]:
        criteriaFeedback.append("Must have at least 1 number")
    if not criteriaResults["hasSpecial"]:
        criteriaFeedback.append("Must have at least 1 special character")
        securityFeedback.append(r'''OWASP recommends using these characters (between double quotes): " !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"''')
    
    if len(securityFeedback) < 3:
        newfeedback = random.sample(SECURITY_RECOMMENDATIONS, 3 - len(securityFeedback))
        for n in newfeedback:
            securityFeedback.append(n)
        
    return criteriaFeedback, securityFeedback

def commonlyUsedCheck(password: str, filename: str = DEFAULT_COMMON_PASSWORD_FILE) -> Optional[bool]:
    """Streams through a common password file to check if given password matches"""
    try:
        path = Path(filename)
        
        # 1. Verify it exists and is a real file (not a directory)
        if not path.is_file():
            print(f"\nError: The password list file '{filename}' was not found.")
            print("Warning: Will run script without common check")
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

def calculateEntropy(password: str) -> Tuple[float, str]:
    """Calculates the Shannon entropy of a password in bits and returns its rating description."""
    
    # Determine character pool size (N) based on included character sets
    poolSize = 0
    if re.search(r"[a-z]", password):
        poolSize += 26
    if re.search(r"[A-Z]", password):
        poolSize += 26
    if re.search(r"\d", password):
        poolSize += 10
    if SPECIAL_CHARS_PATTERN.search(password):
        # Standard ASCII special characters pool approximation (~32-33)
        poolSize += 32
    
    if poolSize == 0:
        poolSize = len(set(password))
        
    # Formula: L * log2(N)
    entropy = len(password) * math.log2(poolSize) if poolSize > 0 else 0.0
    entropyRounded = round(entropy, 2)
    
    if entropyRounded < 40:
        entropyRating = "Low (Predictable / Vulnerable)"
    elif entropyRounded < 60:
        entropyRating = "Moderate (Acceptable)"
    elif entropyRounded < 80:
        entropyRating = "High (Strong Randomness)"
    else:
        entropyRating = "Very High (Cryptographic Grade)"
        
    return entropyRounded, entropyRating

# ==========================================
# ORCHESTRATION
# ==========================================

def printResults(strength: StrengthTier, criteriaFeedback: List[str], securityFeedback: List[str], isCommon: Optional[bool], entropy: float, entropyRating: str) -> None:
    """Formats and displays evaluation results, entropy, and security recommendations"""
    RESET = "\033[0m"
    print(f"\nPassword Strength: {strength.ansi_color}{strength}{RESET}")
    print(f"Entropy:           {entropy} bits [{entropyRating}]")

    if criteriaFeedback:
        print("\nAreas for Improvement:")
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
    strength = StrengthTier.getStrengthValue(criteriaResults)
    criteriaFeedback, strengthFeedback = getFeedback(criteriaResults)
    isCommon = commonlyUsedCheck(password, filename)
    entropy, entropyRating = calculateEntropy(password)

    printResults(strength, criteriaFeedback, strengthFeedback, isCommon, entropy, entropyRating)

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