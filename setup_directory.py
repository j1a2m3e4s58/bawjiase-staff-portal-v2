from app import app, db, User, bcrypt

# Create 5 Dummy Staff Members
staff_data = [
    ("Kwesi Arthur", "055-123-4567", "kwesi@bawjiasearearuralbank.com", "Branch Manager", "Kasoa Main"),
    ("Ama Serwaa", "024-987-6543", "ama@bawjiasearearuralbank.com", "Teller", "Head Office"),
    ("John Dumelo", "020-555-0199", "john@bawjiasearearuralbank.com", "Loan Officer", "Adeiso"),
    ("Efya Nokturnal", "027-444-3322", "efya@bawjiasearearuralbank.com", "HR Officer", "Head Office"),
    ("Shatta Wale", "026-111-2233", "shatta@bawjiasearearuralbank.com", "Security Lead", "Offakor")
]

with app.app_context():
    # Create tables if missing
    db.create_all()
    
    hashed_pw = bcrypt.generate_password_hash("password123").decode('utf-8')

    for name, phone, email, role, branch in staff_data:
        # Check if user exists
        if not User.query.filter_by(email=email).first():
            user = User(
                fullname=name,
                phone=phone,
                email=email,
                password=hashed_pw,
                role=role,
                department="Operations",
                branch=branch,
                is_active_user=True
            )
            db.session.add(user)
            print(f"Added: {name}")
    
    db.session.commit()
    print("\nSUCCESS: Directory populated! Run 'python app.py' and login.")