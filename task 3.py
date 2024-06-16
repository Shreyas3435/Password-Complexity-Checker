import re

def check_password_complexity(password):
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    digit_criteria = bool(re.search(r'\d', password))
    special_char_criteria = bool(re.search(r'[\W_]', password))

    complexity_score = sum([
        length_criteria,
        uppercase_criteria,
        lowercase_criteria,
        digit_criteria,
        special_char_criteria
    ])

    strength = {
        5: "Very Strong",
        4: "Strong",
        3: "Medium",
        2: "Weak",
        1: "Very Weak",
        0: "Extremely Weak"
    }[complexity_score]

    return complexity_score, strength

def provide_feedback(password):
    feedback = []
    
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        feedback.append("Password should include at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        feedback.append("Password should include at least one lowercase letter.")
    if not re.search(r'\d', password):
        feedback.append("Password should include at least one digit.")
    if not re.search(r'[\W_]', password):
        feedback.append("Password should include at least one special character.")

    if not feedback:
        feedback.append("Your password is strong. Good job!")

    return feedback

def main():
    print("Password Complexity Checker")
    password = input("Enter a password to check its strength: ")

    score, strength = check_password_complexity(password)
    feedback = provide_feedback(password)

    print(f"\nPassword Complexity Score: {score}/5")
    print(f"Password Strength: {strength}")
    print("\nFeedback:")
    for comment in feedback:
        print(f"- {comment}")

if __name__ == "__main__":
    main()
