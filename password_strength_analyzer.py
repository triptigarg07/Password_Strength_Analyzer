import math
import re
import requests

class PasswordStrengthAnalyzer:
    def __init__(self, common_passwords_url='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt'):
        self.common_passwords = set()
        try:
            response = requests.get(common_passwords_url)
            self.common_passwords = set(response.text.splitlines())
        except:
            print("Warning: Could not download common passwords list. Some checks will be limited.")

    def calculate_entropy(self, password):
        """Calculate password entropy based on character set complexity."""
        character_sets = {
            'lowercase': r'[a-z]',
            'uppercase': r'[A-Z]',
            'numbers': r'\d',
            'symbols': r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]'
        }
        
        # Determine character set complexity
        charset_size = 0
        if re.search(character_sets['lowercase'], password):
            charset_size += 26
        if re.search(character_sets['uppercase'], password):
            charset_size += 26
        if re.search(character_sets['numbers'], password):
            charset_size += 10
        if re.search(character_sets['symbols'], password):
            charset_size += 32
        
        # Calculate entropy
        return len(password) * math.log2(charset_size) if charset_size > 0 else 0

    def evaluate_password(self, password):
        """Comprehensive password strength evaluation."""
        # Basic checks
        if len(password) < 8:
            return {
                'strength': 'Weak',
                'score': 1,
                'reasons': ['Password too short']
            }
        
        # Check against common passwords
        if password.lower() in (p.lower() for p in self.common_passwords):
            return {
                'strength': 'Weak',
                'score': 1,
                'reasons': ['Password is in common passwords list']
            }
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Strength categorization
        if entropy < 40:
            strength = 'Weak'
            score = 1
        elif entropy < 60:
            strength = 'Medium'
            score = 2
        elif entropy < 80:
            strength = 'Strong'
            score = 3
        else:
            strength = 'Very Strong'
            score = 4
        
        # Detailed analysis
        reasons = []
        if not re.search(r'[A-Z]', password):
            reasons.append('No uppercase letters')
        if not re.search(r'[a-z]', password):
            reasons.append('No lowercase letters')
        if not re.search(r'\d', password):
            reasons.append('No numbers')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            reasons.append('No special characters')
        
        return {
            'strength': strength,
            'score': score,
            'entropy': round(entropy, 2),
            'reasons': reasons
        }

def main():
    analyzer = PasswordStrengthAnalyzer()
    
    # Example usage
    test_passwords = [
        'password123',
        'StrongP@ssw0rd!',
        'weak',
        'ComplexPasswordWith!23456'
    ]
    
    for pwd in test_passwords:
        result = analyzer.evaluate_password(pwd)
        print(f"Password: {pwd}")
        print(f"Strength: {result['strength']}")
        print(f"Score: {result['score']}/4")
        print(f"Entropy: {result.get('entropy', 'N/A')}")
        if result['reasons']:
            print("Improvement suggestions:")
            for reason in result['reasons']:
                print(f"- {reason}")
        print()

if __name__ == '__main__':
    main()