from io import StringIO
import unittest
from unittest.mock import patch
from password_strength_checker import criteriaCheck, getStrengthValue, getFeedback, additionalFeedback, commonlyUsedCheck, isPasswordStrong, main, printResults

class test_criteria(unittest.TestCase):
    def test_length(self):
        self.assertFalse(criteriaCheck("123")["hasMinLength"]);
        self.assertTrue(criteriaCheck("12345678")["hasMinLength"]);
    
    def test_lowercase(self):
        self.assertFalse(criteriaCheck("ABC")["hasLowercase"]);
        self.assertTrue(criteriaCheck("ABc")["hasLowercase"]);
    
    def test_uppercase(self):
        self.assertFalse(criteriaCheck("abc")["hasUppercase"]);
        self.assertTrue(criteriaCheck("abC")["hasUppercase"]);
    
    def test_digit(self):
        self.assertFalse(criteriaCheck("abc")["hasDigit"]);
        self.assertTrue(criteriaCheck("abc1")["hasDigit"]);
    
    def test_special(self):
        self.assertFalse(criteriaCheck("abc")["hasSpecial"]);
        self.assertTrue(criteriaCheck("abc ")["hasSpecial"]);
        
class test_StrengthValue(unittest.TestCase):
    def setUp(self):
        self.criteriaResults = {
            "hasMinLength": False,
            "hasLowercase": False,
            "hasUppercase": False,
            "hasDigit": False,
            "hasSpecial": False
        }
    
    def tearDown(self):
        del self.criteriaResults

    def test_strength_very_weak(self):
        self.assertEqual(getStrengthValue(self.criteriaResults), "Very Weak");
        self.criteriaResults[0] = True;
        self.assertEqual(getStrengthValue(self.criteriaResults), "Very Weak");
        
    def test_strength_weak(self):
        self.criteriaResults[0] = True;
        self.criteriaResults[1] = True;
        self.assertEqual(getStrengthValue(self.criteriaResults), "Weak");
        
    def test_strength_good(self):
        self.criteriaResults[0] = True;
        self.criteriaResults[1] = True;
        self.criteriaResults[2] = True;
        self.assertEqual(getStrengthValue(self.criteriaResults), "Good");
    
    def test_strength_very_good(self):
        self.criteriaResults[0] = True;
        self.criteriaResults[1] = True;
        self.criteriaResults[2] = True;
        self.criteriaResults[3] = True;
        self.assertEqual(getStrengthValue(self.criteriaResults), "Very Good");
    
    def test_strength_strong(self):
        self.criteriaResults[0] = True;
        self.criteriaResults[1] = True;
        self.criteriaResults[2] = True;
        self.criteriaResults[3] = True;
        self.criteriaResults[4] = True;
        self.assertEqual(getStrengthValue(self.criteriaResults), "Strong");

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
        self.assertEqual(getFeedback(self.criteriaResults)[0], []);
    
    def test_length_feedback(self):
        self.criteriaResults["hasMinLength"] = False;
        expectedCriteriaFeedback = "Must be at least 8 characters";
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0]);
        expectedSecurityFeedback = "Passwords shorter than 8 characters are considered to be weak (NIST SP800-63B)";
        self.assertIn(expectedSecurityFeedback, getFeedback(self.criteriaResults)[1]);
    
    def test_lowercase_feedback(self):
        self.criteriaResults["hasLowercase"] = False;
        expectedCriteriaFeedback = "Must have at least 1 lowercase letter";
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0]);
    
    def test_uppercase_feedback(self):
        self.criteriaResults["hasUppercase"] = False;
        expectedCriteriaFeedback = "Must have at least 1 uppercase letter";
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0]);
    
    def test_digit_feedback(self):
        self.criteriaResults["hasDigit"] = False;
        expectedCriteriaFeedback = "Must have at least 1 number";
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0]);
    
    def test_special_feedback(self):
        self.criteriaResults["hasSpecial"] = False;
        expectedCriteriaFeedback = "Must have at least 1 special character";
        self.assertIn(expectedCriteriaFeedback, getFeedback(self.criteriaResults)[0]);
        expectedSecurityFeedback = "OWASP recommends using these characters (between double quotes): \" !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~\"";
        self.assertIn(expectedSecurityFeedback, getFeedback(self.criteriaResults)[1]);
        
    #check for 3 cases of additional feedback 
    def test_add_3_feedback(self):
        outputResults = getFeedback(self.criteriaResults)[1];
        sharedValue = set(outputResults) & set(additionalFeedback);
        self.assertEqual(len(outputResults), 3);
        self.assertEqual(len(sharedValue), 3);
    
    def test_add_2_feedback(self):
        self.criteriaResults["hasMinLength"] = False;
        outputResults = getFeedback(self.criteriaResults)[1];
        sharedValue = set(outputResults) & set(additionalFeedback);
        self.assertEqual(len(outputResults), 3);
        self.assertEqual(len(sharedValue), 2);
    
    def test_add_1_feedback(self):
        self.criteriaResults["hasMinLength"] = False;
        self.criteriaResults["hasSpecial"] = False;
        outputResults = getFeedback(self.criteriaResults)[1];
        sharedValue = set(outputResults) & set(additionalFeedback);
        self.assertEqual(len(outputResults), 3);
        self.assertEqual(len(sharedValue), 1);

class test_commonlyUsed(unittest.TestCase):
    def test_common_password(self):
        self.assertTrue(commonlyUsedCheck("1q2w3e4r5t6y"));
        self.assertTrue(commonlyUsedCheck("cjkysirj"));
        self.assertTrue(commonlyUsedCheck("L58jkdjP!"));
    
    def test_not_common_password(self):
        self.assertFalse(commonlyUsedCheck("KS%@Ncm34agd692}"));
        self.assertFalse(commonlyUsedCheck("c@#SkyF982irj"));
        self.assertFalse(commonlyUsedCheck("J*6was1s@@"));
        
    @patch('password_strength_checker.open')
    @patch('sys.stdout', new_callable=StringIO)
    def test_read_file_exception(self, stdout_mock, mock_open):
        mock_open.side_effect = FileNotFoundError
        result = commonlyUsedCheck('password')
        self.assertFalse(result)
        self.assertIn("An error occurred:", stdout_mock.getvalue());

class test_printResults(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_print_criteria_feedback(self, stdout_mock):
        printResults("weak", ["test1", "test2"], [], False);
        self.assertIn("Password Strength: weak", stdout_mock.getvalue());
        self.assertIn(" - test1\n - test2", stdout_mock.getvalue());
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_print_common_true(self, stdout_mock):
        printResults("", [], [], True);
        expected_string1 = "\nYour password is among the most commonly used and could be easily cracked.";
        self.assertIn(expected_string1, stdout_mock.getvalue());
        expected_string2 = "For your protection, please update it to something more secure!";
        self.assertIn(expected_string2, stdout_mock.getvalue());
        
    @patch('sys.stdout', new_callable=StringIO)
    def test_print_common_false(self, stdout_mock):
        printResults("", [], [], False);
        expected_string = "\nYour password is not in the Seclist top password list being used here."
        self.assertIn(expected_string, stdout_mock.getvalue())
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_print_strength_feedback(self, stdout_mock):
        printResults("", [], ["test1", "test2"], False);
        self.assertIn("\nSecurity Recommendations:", stdout_mock.getvalue());
        self.assertIn(" - test1\n - test2", stdout_mock.getvalue());

class test_isPasswordStrong(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_no_password_given(self,stdout_mock):
        isPasswordStrong("");
        self.assertIn("Invalid Password\n", stdout_mock.getvalue());
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_call_printResults(self, stdout_mock):
        isPasswordStrong("password");
        self.assertIn("Password Strength:", stdout_mock.getvalue());
        self.assertIn("\nSecurity Recommendations:", stdout_mock.getvalue());
        
class test_main(unittest.TestCase):
    @patch('builtins.input', return_value='')
    @patch('sys.stdout', new_callable=StringIO)
    def test_no_input(self, stdout_mock, mock_input):
        main();
        mock_input.assert_called_once_with("Enter Password: ");
        self.assertIn("Invalid Password\n", stdout_mock.getvalue());
        
    @patch('builtins.input', return_value='password')
    @patch('sys.stdout', new_callable=StringIO)
    def test_with_input(self, stdout_mock, mock_input):
        main();
        mock_input.assert_called_once_with("Enter Password: ");
        self.assertIn("Password Strength: ", stdout_mock.getvalue());