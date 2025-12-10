from app import app, db, Form, User
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

def setup_google_drive_links():
    with app.app_context():
        print("--- LINKING FORMS (EXTRACTING IDs) ---")
        
        # 1. Reset Database
        db.create_all()
        Form.query.delete()

        # 2. Ensure Admin Exists
        if not User.query.filter_by(email="admin@bawjiase.com").first():
            hashed_pw = bcrypt.generate_password_hash("password123").decode('utf-8')
            db.session.add(User(fullname="System Admin", phone="0244000000", email="admin@bawjiase.com", password=hashed_pw, role="Super Admin", branch="Head Office", department="IT"))

        # 3. YOUR LINKS (I have extracted the IDs for you based on the links you sent)
        # Format: (Title, Category, File_ID)
        
        forms_data = [
            ("2025 End of Year Appraisal", "HR", "1x0qDGKMudExHenT46QqCMm8ln0J2RjTE"),
            ("Code of Conduct", "Compliance", "1Fu97vLE4A_TAkiwLu__8vNRvsiCudjx7"),
            ("New Medical Forms", "HR", "1iGpcNdrJbPQ0C3PRvs1AW3JXOLK4SRMH"),
            ("Oath of Secrecy", "Compliance", "1Qlab6ipjgP2aw2wOYU1SO99cX8tsf1kj"),
            ("Staff Family Update Form", "General", "1LxW2ERPBr6N8qwb4yQ22jy8B-4OO2qZ5")
        ]

        count = 0
        for title, category, file_id in forms_data:
            # We store ONLY the Google File ID in the database
            new_form = Form(title=title, category=category, filename=file_id)
            db.session.add(new_form)
            count += 1
            print(f"   [LINKED] {title} (ID: {file_id})")

        db.session.commit()
        print(f"--- SUCCESS: {count} forms linked with Download options. ---")

if __name__ == '__main__':
    setup_google_drive_links()