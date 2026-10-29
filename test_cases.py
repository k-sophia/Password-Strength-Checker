from io import StringIO
import unittest
from unittest.mock import patch
import tempfile
from password_strength_checker import (
    SECURITY_RECOMMENDATIONS,
    criteriaCheck,
    StrengthTier, 
    getFeedback,
    commonlyUsedCheck,
    printResults,
    isPasswordStrong,
    main
)

class test_criteria(unittest.TestCase):
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
            # special char checl
            ("abc", "hasSpecial", False),
            ("abc ", "hasSpecial", True),
        ]
        for password, key, expected in test_cases:
            with self.subTest(password=password, key=key):
                self.assertEqual(criteriaCheck(password)[key], expected)
        
class test_StrengthValue(unittest.TestCase):
    def setUp(self):
        self.criteriaResults = {
            "hasMinLength": False,
            "hasLowercase": False,
            "hasUppercase": False,
            "hasDigit": False,
            "hasSpecial": False
        }

    def test_strength_all_false_is_very_weak(self):
        self.assertEqual(StrengthTier.getStrengthValue(self.criteriaResults), StrengthTier.VERY_WEAK)

    def test_strength_progressive_tiers(self):
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

class test_feedback(unittest.TestCase):
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
        expectedCriteriaFeedback = "Must be at least 15 characters"
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0])
        expectedSecurityFeedback = "NIST recommends at least 15 characters long to enhance security (NIST SP800-63B)"
        self.assertIn(expectedSecurityFeedback, getFeedback(self.criteriaResults)[1])
    
    def test_lowercase_feedback(self):
        self.criteriaResults["hasLowercase"] = False
        expectedCriteriaFeedback = "Must have at least 1 lowercase letter"
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0])
    
    def test_uppercase_feedback(self):
        self.criteriaResults["hasUppercase"] = False
        expectedCriteriaFeedback = "Must have at least 1 uppercase letter"
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0])
    
    def test_digit_feedback(self):
        self.criteriaResults["hasDigit"] = False
        expectedCriteriaFeedback = "Must have at least 1 number"
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0])
    
    def test_special_feedback(self):
        self.criteriaResults["hasSpecial"] = False
        expectedCriteriaFeedback = "Must have at least 1 special character"
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0])
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
    
    def test_add_1_feedback(self):
        self.criteriaResults["hasMinLength"] = False
        self.criteriaResults["hasSpecial"] = False
        outputResults = getFeedback(self.criteriaResults)[1]
        sharedValue = set(outputResults) & set(SECURITY_RECOMMENDATIONS)
        self.assertEqual(len(outputResults), 3)
        self.assertEqual(len(sharedValue), 1)
    
    def test_add_1_additional_feedback(self):
        self.criteriaResults["hasMinLength"] = False
        self.criteriaResults["hasSpecial"] = False
        securityFeedback = getFeedback(self.criteriaResults)[1]
        sharedFeedback = set(securityFeedback) & set(SECURITY_RECOMMENDATIONS)
        self.assertEqual(len(securityFeedback), 3)
        self.assertEqual(len(sharedFeedback), 1)

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

class test_printResults(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_criteria_feedback_omitted_when_empty(self, stdout_mock):
        printResults(StrengthTier.WEAK, [], [], False)
        self.assertNotIn("Areas for Improvement", stdout_mock.getvalue())
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_criteria_feedback_displayed_when_present(self, stdout_mock):
        printResults(StrengthTier.WEAK, ["test1", "test2"], [], False)
        output = stdout_mock.getvalue()
        self.assertIn("Areas for Improvement", output)
        self.assertIn(" - test1", output)
        self.assertIn(" - test2", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_common_password_warning_displayed(self, stdout_mock):
        printResults(StrengthTier.VERY_WEAK, [], [], True)
        output = stdout_mock.getvalue()
        self.assertIn("Your password is among the most commonly used and could be easily cracked", output)
        self.assertIn("please update it to something more secure!", output)
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_common_password_safe_message_displayed(self, stdout_mock):
        printResults(StrengthTier.VERY_WEAK, [], [], False)
        self.assertIn("Your password is not in the Seclist top password list being used here", stdout_mock.getvalue())
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_security_recommendations_displayed(self, stdout_mock):
        printResults(StrengthTier.VERY_WEAK, [], ["test1", "test2"], False)
        output = stdout_mock.getvalue()
        self.assertIn("Security Recommendations:", output)
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
        self.assertIn("\nSecurity Recommendations:", stdout_mock.getvalue())
        
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