# Password Strength Analyzer

## Overview
Python script to analyze password complexity using entropy calculation and comprehensive security checks.

## Features
- Entropy-based strength scoring
- Common password list check
- Detailed strength analysis
- Programmatic password evaluation

## Usage
```python
from password_strength_analyzer import PasswordStrengthAnalyzer

analyzer = PasswordStrengthAnalyzer()
result = analyzer.evaluate_password('YourPassword123!')
print(result)
