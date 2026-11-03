from io import StringIO
import unittest
from unittest.mock import patch
import tempfile
from password_strength_checker import (
    SECURITY_RECOMMENDATIONS,
    StrengthTier,
    AnalysisResult,
    criteriaCheck,
    analyzeStructuralPatterns,
    calculateEntropy,
    getFeedback,
    getStructuralFeedback,
    commonlyUsedCheck,
    printResults,
    isPasswordStrong,
    main
)

# ==========================================
# 1. VALIDATION AND STRENGTH SCORING
# ==========================================

class test_criteriaCheck(unittest.TestCase):
    def test_criteria_validations(self):
        test_cases = [
            # length check
            ("123", "hasMinLength", False),
            ("hasminimallength", "hasMinLength", True),
            # case check
            ("ABC", "hasLowercase", False),
            ("ABc", "hasLowercase", True),
            ("abc", "hasUppercase", False),
            ("abC", "hasUppercase", True),
            # digit check
            ("abc", "hasDigit", False),
            ("abc1", "hasDigit", True),
            # special char check
            ("abc", "hasSpecial", False),
            ("abc ", "hasSpecial", True),
        ]
        for password, key, expected in test_cases:
            with self.subTest(password=password, key=key):
                self.assertEqual(criteriaCheck(password)[key], expected)

class test_analyzeStructuralPatterns(unittest.TestCase):
    def test_structural_pattern_validations(self):
        test_cases = [
            # repetition check
            ("qwerty", "hasRepetitions", False),
            ("111", "hasRepetitions", True),
            # numeric sequence check
            ("102938", "hasNumericSequence", False),
            ("ASC123", "hasNumericSequence", True),
            ("DESC321", "hasNumericSequence", True),
            # alphabetic sequence check
            ("qwerty", "hasAlphabeticalSequence", False),
            ("abc", "hasAlphabeticalSequence", True),
        ]
        for password, key, expected in test_cases:
            with self.subTest(password=password, key=key):
                self.assertEqual(analyzeStructuralPatterns(password)[key], expected)

class test_StrengthValue(unittest.TestCase):
    def test_ansi_color_property(self):
        self.assertEqual(StrengthTier.VERY_WEAK.ansiColor, "\033[91m")
        self.assertEqual(StrengthTier.WEAK.ansiColor, "\033[38;5;208m")
        self.assertEqual(StrengthTier.GOOD.ansiColor, "\033[33m")
        self.assertEqual(StrengthTier.VERY_GOOD.ansiColor, "\033[38;5;71m")
        self.assertEqual(StrengthTier.STRONG.ansiColor, "\033[1m\033[32m")
    
    def setUp(self):
        self.criteriaResults = {
            "hasMinLength": False,
            "hasLowercase": False,
            "hasUppercase": False,
            "hasDigit": False,
            "hasSpecial": False
        }
        
        self.structuralResults = {
            "hasRepetitions": False,
            "hasNumericSequence": False,
            "hasAlphabeticalSequence": False
        }

    def test_criteria_strength_all_false(self):
        self.assertEqual(StrengthTier.getStrengthValue(self.criteriaResults), StrengthTier.VERY_WEAK)

    def test_criteria_strength_progressive_tiers(self):
        steps = [
            ("hasMinLength", StrengthTier.VERY_WEAK),
            ("hasLowercase", StrengthTier.WEAK),
            ("hasUppercase", StrengthTier.GOOD),
            ("hasDigit", StrengthTier.VERY_GOOD),
            ("hasSpecial", StrengthTier.STRONG),
        ]
        
        for key, expected_strength in steps:
            self.criteriaResults[key] = True
            with self.subTest(added_key=key):
                self.assertEqual(StrengthTier.getStrengthValue(self.criteriaResults), expected_strength)

    def test_structural_strength_all_false(self):
        self.assertEqual(StrengthTier.getStructuralStrengthValue(self.structuralResults), StrengthTier.STRONG)

    def test_structural_strength_progressive_tiers(self):
        steps = [
            ("hasRepetitions", StrengthTier.GOOD),
            ("hasNumericSequence", StrengthTier.WEAK),
            ("hasAlphabeticalSequence", StrengthTier.VERY_WEAK),
        ]
        for key, expected_strength in steps:
            self.structuralResults[key] = True
            with self.subTest(added_key=key):
                self.assertEqual(StrengthTier.getStructuralStrengthValue(self.structuralResults), expected_strength)

class test_calculateEntropy(unittest.TestCase):
    def test_low_entropy(self):
        entropyVal, ratingVal = calculateEntropy("aaaaaa")
        self.assertLess(entropyVal, 30.0)
        self.assertIn("Low", ratingVal)

    def test_moderate_entropy(self):
        entropyVal, ratingVal = calculateEntropy("abcdefghijkl")
        self.assertTrue(40.0 <= entropyVal < 60.0)
        self.assertIn("Moderate", ratingVal)

    def test_high_entropy(self):
        entropyVal, ratingVal = calculateEntropy("Abcdef123456")
        self.assertTrue(60.0 <= entropyVal < 80.0)
        self.assertIn("High", ratingVal)

    def test_very_high_entropy(self):
        entropyVal, ratingVal = calculateEntropy("K8#mP9$xL2!qR5%v")
        self.assertGreaterEqual(entropyVal, 80.0)
        self.assertIn("Very High", ratingVal)

    def test_fallback_pool_size(self):
        entropyVal, ratingVal = calculateEntropy("ééééééééééééééé")
        self.assertEqual(entropyVal, 0.0)
        self.assertIn("Low", ratingVal)

# ==========================================
# 2. EXTERNAL CHECKS AND FEEDBACK
# ==========================================

class test_commonlyUsed(unittest.TestCase):
    def test_common_passwords(self):
        for pwd in ["1q2w3e4r5t6y", "cjkysirj", "L58jkdjP!"]:
            with self.subTest(password=pwd):
                self.assertTrue(commonlyUsedCheck(pwd))
    
    def test_not_common_passwords(self):
        for pwd in ["KS%@Ncm34agd692}", "c@#SkyF982irj", "J*6was1s@@"]:
            with self.subTest(password=pwd):
                self.assertFalse(commonlyUsedCheck(pwd))
        
    @patch('pathlib.Path.is_file', return_value=False)
    @patch('sys.stdout', new_callable=StringIO)
    def test_invalid_file_path(self, stdout_mock, mock_is_file):
        result = commonlyUsedCheck('password', filename="bad_path.txt")
        self.assertIsNone(result)
        self.assertIn("Error: The password list file 'bad_path.txt' was not found.", stdout_mock.getvalue())
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_invalid_file_extension(self, stdout_mock):
        # Creates a temporary file ending in .csv on your disk
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=True) as tmp:
            # Pass the temp file's actual path string to your function
            result = commonlyUsedCheck('password', filename=tmp.name)
            
            self.assertIsNone(result)
            expected_string = f"Error: '{tmp.name}' must be a .txt file."
            self.assertIn(expected_string, stdout_mock.getvalue()) # (or capture stdout)

    @patch('pathlib.Path.is_file', return_value=True)
    @patch('pathlib.Path.stat')
    @patch('sys.stdout', new_callable=StringIO)
    def test_file_size_exceeded(self, stdout_mock, mock_stat, mock_is_file):
        # Mock st_size to return 60 MB (exceeding the 50 MB limit)
        mock_stat.return_value.st_size = 60 * 1024 * 1024
        result = commonlyUsedCheck('password')
        self.assertIsNone(result)
        expected_string = "Error: File size exceeds the maximum allowed limit (50MB)."
        self.assertIn(expected_string, stdout_mock.getvalue())
    
    @patch('pathlib.Path.is_file', return_value=True)
    @patch('pathlib.Path.stat')
    @patch('sys.stdout', new_callable=StringIO)
    def test_read_file_generic_exception(self, stdout_mock, mock_stat, mock_is_file):
        mock_stat.side_effect = PermissionError("Permission denied")
        result = commonlyUsedCheck('password')
        self.assertIsNone(result)
        expected_string = "An error occurred: Permission denied"
        self.assertIn(expected_string, stdout_mock.getvalue())

class test_getFeedback(unittest.TestCase):
    def setUp(self):
        self.criteriaResults = {
            "hasMinLength": True,
            "hasLowercase": True,
            "hasUppercase": True,
            "hasDigit": True,
            "hasSpecial": True
        }
    
    def tearDown(self):
        del self.criteriaResults

    def test_no_criteria_feedback(self):
        self.assertEqual(getFeedback(self.criteriaResults)[0], [])
    
    def test_length_feedback(self):
        self.criteriaResults["hasMinLength"] = False
        self.assertIn("Must be at least 15 characters", getFeedback(self.criteriaResults)[0])
        self.assertIn("NIST recommends at least 15 characters long to enhance security (NIST SP800-63B)", getFeedback(self.criteriaResults)[1])
    
    def test_lowercase_feedback(self):
        self.criteriaResults["hasLowercase"] = False
        self.assertIn("Must have at least 1 lowercase letter", getFeedback(self.criteriaResults)[0])
    
    def test_uppercase_feedback(self):
        self.criteriaResults["hasUppercase"] = False
        self.assertIn("Must have at least 1 uppercase letter", getFeedback(self.criteriaResults)[0])
    
    def test_digit_feedback(self):
        self.criteriaResults["hasDigit"] = False
        self.assertIn("Must have at least 1 number", getFeedback(self.criteriaResults)[0])
    
    def test_special_feedback(self):
        self.criteriaResults["hasSpecial"] = False
        self.assertIn("Must have at least 1 special character", getFeedback(self.criteriaResults)[0])
        expectedSecurityFeedback = r'''OWASP recommends using these characters (between double quotes): " !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"'''
        self.assertIn(expectedSecurityFeedback, getFeedback(self.criteriaResults)[1])
    
    def test_add_3_additional_feedback(self):
        securityFeedback = getFeedback(self.criteriaResults)[1]
        sharedFeedback = set(securityFeedback) & set(SECURITY_RECOMMENDATIONS)
        self.assertEqual(len(securityFeedback), 3)
        self.assertEqual(len(sharedFeedback), 3)
        
    def test_add_2_additional_feedback(self):
        self.criteriaResults["hasMinLength"] = False
        securityFeedback = getFeedback(self.criteriaResults)[1]
        sharedFeedback = set(securityFeedback) & set(SECURITY_RECOMMENDATIONS)
        self.assertEqual(len(securityFeedback), 3)
        self.assertEqual(len(sharedFeedback), 2)
    
    def test_add_1_additional_feedback(self):
        self.criteriaResults["hasMinLength"] = False
        self.criteriaResults["hasSpecial"] = False
        securityFeedback = getFeedback(self.criteriaResults)[1]
        sharedFeedback = set(securityFeedback) & set(SECURITY_RECOMMENDATIONS)
        self.assertEqual(len(securityFeedback), 3)
        self.assertEqual(len(sharedFeedback), 1)

class test_getStructuralFeedback(unittest.TestCase):
    def setUp(self):
        self.structuralResults = {
            "hasRepetitions": False,
            "hasNumericSequence": False,
            "hasAlphabeticalSequence": False
        }

    def test_no_advanced_feedback_when_clean(self):
        self.assertEqual(getStructuralFeedback(self.structuralResults), [])

    def test_repetition_feedback(self):
        self.structuralResults["hasRepetitions"] = True
        expected = "Contains 3 or more consecutive identical characters (e.g., 'aaa' or '111')"
        self.assertIn(expected, getStructuralFeedback(self.structuralResults))

    def test_numeric_sequence_feedback(self):
        self.structuralResults["hasNumericSequence"] = True
        expected = "Contains numeric sequences (e.g., '123' or '890')"
        self.assertIn(expected, getStructuralFeedback(self.structuralResults))

    def test_alphabetical_sequence_feedback(self):
        self.structuralResults["hasAlphabeticalSequence"] = True
        expected = "Contains alphabetical sequences (e.g., 'abc' or 'zyx')"
        self.assertIn(expected, getStructuralFeedback(self.structuralResults))

# ==========================================
# 3. ORCHESTRATION
# ==========================================

class test_printResults(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_criteria_feedback_omitted_when_empty(self, stdout_mock):
        criteriaResults = AnalysisResult(
            strength=StrengthTier.WEAK,
            feedback=[],
            entropy=48.2,
            entropyRating="",
        )
        structuralResults = AnalysisResult(
            strength=StrengthTier.WEAK,
            feedback=[]
        )
        
        printResults(False, criteriaResults, structuralResults, [])
        self.assertNotIn("Areas for Improvement", stdout_mock.getvalue())
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_criteria_feedback_displayed_when_present(self, stdout_mock):
        criteriaResults = AnalysisResult(
            strength=StrengthTier.WEAK,
            feedback=["test1", "test2"],
            entropy=48.2,
            entropyRating="",
        )
        structuralResults = AnalysisResult(
            strength=StrengthTier.WEAK,
            feedback=[]
        )
        
        printResults(False, criteriaResults, structuralResults, [])
        output = stdout_mock.getvalue()
        self.assertIn("Areas for Improvement", output)
        self.assertIn(" - test1", output)
        self.assertIn(" - test2", output)
        
    @patch('sys.stdout', new_callable=StringIO)
    def test_common_password_messages(self, stdout_mock):
        criteriaResults = AnalysisResult(
            strength=StrengthTier.VERY_WEAK,
            feedback=[],
            entropy=48.2,
            entropyRating="",
        )
        structuralResults = AnalysisResult(
            strength=StrengthTier.VERY_WEAK,
            feedback=[]
        )
        
        test_cases = [
            (True, "Your password is among the most commonly used"),
            (False, "Your password is not in the Seclist top password list")
        ]
        
        for isCommon, expected_text in test_cases:
            with self.subTest(isCommon=isCommon):
                stdout_mock.seek(0)
                stdout_mock.truncate(0)
                
                printResults(isCommon, criteriaResults, structuralResults, [])
                self.assertIn(expected_text, stdout_mock.getvalue())
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_security_recommendations_displayed(self, stdout_mock):
        criteriaResults = AnalysisResult(
            strength=StrengthTier.VERY_WEAK,
            feedback=[],
            entropy=48.2,
            entropyRating="",
        )
        structuralResults = AnalysisResult(
            strength=StrengthTier.VERY_WEAK,
            feedback=[]
        )
        
        printResults(False, criteriaResults, structuralResults, securityFeedback=["test1", "test2"])
        output = stdout_mock.getvalue()
        self.assertIn("=== Security Recommendations ===", output)
        self.assertIn(" - test1", output)
        self.assertIn(" - test2", output)

class test_isPasswordStrong(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_invalid_passwords(self, stdout_mock):
        for invalid_pwd in ["", " "]:
            with self.subTest(pwd=invalid_pwd):
                isPasswordStrong(invalid_pwd)
                self.assertIn("Invalid Password\n", stdout_mock.getvalue())
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_call_printResults(self, stdout_mock):
        isPasswordStrong("password")
        self.assertIn("Password Strength:", stdout_mock.getvalue())
        self.assertIn("\n=== Security Recommendations ===", stdout_mock.getvalue())
        
class test_main(unittest.TestCase):
    @patch('sys.argv', ['password_strength_checker.py'])
    @patch('builtins.input', return_value='')
    @patch('sys.stdout', new_callable=StringIO)
    def test_no_input(self, stdout_mock, mock_input):
        main()
        mock_input.assert_called_once_with("Enter Password: ")
        self.assertIn("Invalid Password\n", stdout_mock.getvalue())
        
    @patch('sys.argv', ['password_strength_checker.py'])
    @patch('builtins.input', return_value='password')
    @patch('sys.stdout', new_callable=StringIO)
    def test_with_input(self, stdout_mock, mock_input):
        main()
        mock_input.assert_called_once_with("Enter Password: ")
        self.assertIn("Password Strength: ", stdout_mock.getvalue())