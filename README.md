# Student-attendance-System
python -m venv venv
# Linux:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

pip install -r requirements.txt
python app.py


Per-student secret PIN (hashed) (friend can’t just type a roll number)
Daily rotating “session code” shown on teacher screen (prevents reusing old screenshots/notes)
Webcam snapshot on each check-in (the main “catch them” mechanism: you get proof)
One attendance per student per day + rate limits + audit logs
