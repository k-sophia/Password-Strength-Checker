import re
import random

passwordStrength = {
    0 : "Very Weak",
    1 : "Very Weak",
    2 : "Weak",
    3 : "Good",
    4 : "Very Good",
    5 : "Strong"
}

additionalFeedback = [
    "Though minimum length is 8, it is recommended to have longer passwords",
    "Update passwords periodically, especially for sensitive accounts",
    "Never use the same password for multiple accounts or services",
    "Avoid the use of common, simple, and predictable passwords",
    "Check if password was previouslt exposed in data breach - such as Have I Been Pwned",
    "Use Multi-Factor Authenticaiton when given the option",
    "Do not use personal information in the password"
]

def criteriaCheck(password):
        
    hasMinLength = len(password) >= 8;
    hasLowercase = re.search(r"[a-z]", password) is not None;
    hasUppercase = re.search(r"[A-Z]", password) is not None;
    hasDigit = re.search(r"\d", password) is not None;
    #" !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
    specialChars = re.compile(' |!|"|#|\$|%|&|\'|\(|\)|\*|\+|,|-|\.|\/|:|;|<|=|>|\?|@|\[|\\|]|\^|_|`|{|\||}|~');
    hasSpecial = specialChars.search(password) is not None;
    
    return {
        "hasMinLength": hasMinLength,
        "hasLowercase": hasLowercase,
        "hasUppercase": hasUppercase,
        "hasDigit": hasDigit,
        "hasSpecial": hasSpecial
    }
    
def getStrengthValue(criteriaResults):
    return passwordStrength[sum(criteriaResults.values())]

def getFeedback(criteriaResults):
    criteriaFeedback = [];
    strengthFeedback = [];
    
    if not criteriaResults["hasMinLength"]:
        criteriaFeedback.append("Must be at least 8 characters");
        strengthFeedback.append("Passwords shorter than 8 characters are considered to be weak (NIST SP800-63B)");
    if not criteriaResults["hasLowercase"]:
        criteriaFeedback.append("Must have at least 1 lowercase letter");
    if not criteriaResults["hasUppercase"]:
        criteriaFeedback.append("Must have at least 1 uppercase letter");
    if not criteriaResults["hasDigit"]:
        criteriaFeedback.append("Must have at least 1 number");
    if not criteriaResults["hasSpecial"]:
        criteriaFeedback.append("Must have at least 1 special character");
        strengthFeedback.append("OWASP recommends using these characters (between double quotes): \" !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~\"");
    
    if len(strengthFeedback) < 3:
        newfeedback = random.sample(additionalFeedback, 3 - len(strengthFeedback))
        for n in newfeedback:
            strengthFeedback.append(n)
        
    return criteriaFeedback, strengthFeedback
    
def commonlyUsedCheck(password):
    try:
        filename = "10-million-password-list-top-1000000.txt";
        with open(filename, "r") as file:
            for line in file:
                if line == password + "\n":
                    return True;
        return False;
    except Exception as e:
        print(f"An error occurred: {e}");
        return False;

def printResults(strength, criteriaFeedback, strengthFeedback, isCommon):

    print("Password Strength: " + strength);
    for c in criteriaFeedback:
        print(" - " + c);
        
    if isCommon:
        print("\nYour password is among the most commonly used and could be easily cracked.")
        print("For your protection, please update it to something more secure!")
    else:
        print("\nYour password is not in the Seclist top password list being used here.")
        
    
    print("\nSecurity Recommendations:");
    for s in strengthFeedback:
        print(" - " + s);

def isPasswordStrong(password):
    if len(password) == 0:
        print("Invalid Password");
        return;
    
    criteriaResults = criteriaCheck(password);
    strength = getStrengthValue(criteriaResults);
    criteriaFeedback, strengthFeedback = getFeedback(criteriaResults);
    isCommon = commonlyUsedCheck(password);

    printResults(strength, criteriaFeedback, strengthFeedback, isCommon);


def main():
    password = input("Enter Password: ");
    isPasswordStrong(password);

if __name__ == '__main__':
    main();