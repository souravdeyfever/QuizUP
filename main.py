from datetime import datetime, timedelta
from typing import Optional, List, Dict

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
import base64
import hashlib
import hmac

import os
import shutil
import docx
import pdfplumber

# --- Config ---
DATABASE_URL = "sqlite:///./quiz.db"
SECRET_KEY = "change-me-please-use-a-secure-random-string"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# --- Database ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# --- Auth helpers ---
# Simple PBKDF2-SHA256 hashing (no external bcrypt dependency needed)
# NOTE: This is suitable for a demo / small project; for production, use a dedicated auth library.

templates = Jinja2Templates(directory="templates")


def get_portal_decor() -> str:
    """Return HTML-styled portal decorations for the dashboard header."""

    return """
    <div style="text-align: center; margin: 1.5rem 0;">
      <div style="font-size: 2.5rem; font-weight: 800; color: #000; text-decoration: underline; letter-spacing: 0.05em;">
        QuizUP
      </div>
      <div style="font-size: 1.2rem; font-weight: 700; color: #555; font-style: italic; margin-top: 0.25rem;">
        Get ready for the test. It&apos;s your day.
      </div>
      <div style="font-size: 28px; font-family: 'Georgia', serif; color: #2b3d8a; font-weight: 700; margin: 1.25rem 0;">
        Best of Luck !!
      </div>
    </div>
    """


def get_footer() -> str:
    """Return HTML for footer branding and copyright link."""

    return """
    <footer style="text-align: center; padding: 1.5rem 0; font-size: 13px; font-family: 'Times New Roman', serif; color: #444;">
      <a href="https://sites.google.com/view/souravdey" style="color: #444; text-decoration: none;">
        All rights are reserved by Sourav Dey
      </a>
    </footer>
    """


templates.env.globals["portal_decor"] = get_portal_decor
templates.env.globals["portal_footer"] = get_footer


def get_password_hash(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return base64.b64encode(salt + key).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        decoded = base64.b64decode(hashed_password.encode("utf-8"))
        salt = decoded[:16]
        key = decoded[16:]
        new_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(key, new_key)
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


def get_user_from_token(db: Session, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None

    return get_user_by_id(db, int(user_id))


def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    else:
        token = request.cookies.get("access_token")

    # We'll allow password reset form to function without needing a logged in user, so nothing else here.

    if not token:
        return None

    user = get_user_from_token(db, token)
    return user


def require_user(user: Optional["User"]):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(user: Optional["User"]):
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def get_current_active_user(user: Optional["User"] = Depends(get_current_user)):
    return require_user(user)


def get_current_admin(user: Optional["User"] = Depends(get_current_user)):
    # Ensures user exists and is an admin.
    return require_admin(require_user(user))


def require_faculty(user: Optional["User"]):
    if not user or user.role != "faculty":
        raise HTTPException(status_code=403, detail="Faculty access required")
    return user


def get_current_faculty(user: Optional["User"] = Depends(get_current_user)):
    return require_faculty(require_user(user))


# --- Models ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="student")  # admin / student

    # Optional student profile fields
    course = Column(String, nullable=True)
    programme = Column(String, nullable=True)
    enrollment_no = Column(String, nullable=True)

    answers = relationship("Answer", back_populates="user")
    sessions = relationship("ExamSession", back_populates="user")


class Exam(Base):
    __tablename__ = "exams"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    course = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    code = Column(String, nullable=True)
    duration_minutes = Column(Integer, nullable=False, default=30)
    description = Column(Text, nullable=True)
    start_at = Column(String, nullable=True)
    end_at = Column(String, nullable=True)
    published = Column(Integer, default=0)
    accepting_responses = Column(Integer, default=1)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    questions = relationship("Question", back_populates="exam")
    sessions = relationship("ExamSession", back_populates="exam")
    creator = relationship("User")


class Question(Base):
    __tablename__ = "questions"

    id = Column(Integer, primary_key=True, index=True)
    exam_id = Column(Integer, ForeignKey("exams.id"), nullable=True)
    question = Column(Text, nullable=False)
    type = Column(String, nullable=False)  # mcq / short / long / match / arrange
    option_a = Column(Text, nullable=True)
    option_b = Column(Text, nullable=True)
    option_c = Column(Text, nullable=True)
    option_d = Column(Text, nullable=True)
    correct_answer = Column(Text, nullable=True)
    max_marks = Column(Integer, nullable=True, default=1)

    exam = relationship("Exam", back_populates="questions")
    answers = relationship("Answer", back_populates="question")


class ExamSession(Base):
    __tablename__ = "exam_sessions"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    exam_id = Column(Integer, ForeignKey("exams.id"), nullable=False)
    started_at = Column(String, nullable=False)
    submitted_at = Column(String, nullable=True)
    locked = Column(Integer, default=0)  # 0/1 flag

    user = relationship("User", back_populates="sessions")
    exam = relationship("Exam", back_populates="sessions")
    answers = relationship("Answer", back_populates="session")


class Answer(Base):
    __tablename__ = "answers"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    question_id = Column(Integer, ForeignKey("questions.id"), nullable=False)
    session_id = Column(Integer, ForeignKey("exam_sessions.id"), nullable=True)
    answer = Column(Text, nullable=True)
    marks = Column(Integer, nullable=True)

    user = relationship("User", back_populates="answers")
    question = relationship("Question", back_populates="answers")
    session = relationship("ExamSession", back_populates="answers")


class ProfileUpdateRequest(Base):
    __tablename__ = "profile_update_requests"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    new_name = Column(String, nullable=True)
    new_email = Column(String, nullable=True)
    new_course = Column(String, nullable=True)
    new_programme = Column(String, nullable=True)
    new_enrollment_no = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")  # pending / approved / rejected
    created_at = Column(String, nullable=False)
    reviewed_at = Column(String, nullable=True)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    student = relationship("User", foreign_keys=[student_id])
    reviewer = relationship("User", foreign_keys=[reviewed_by])


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String, primary_key=True)
    value = Column(String, nullable=True)


# --- Settings helpers ---

def get_setting(db: Session, key: str, default: Optional[str] = None) -> Optional[str]:
    setting = db.query(Setting).filter(Setting.key == key).first()
    return setting.value if setting else default


def set_setting(db: Session, key: str, value: str) -> None:
    setting = db.query(Setting).filter(Setting.key == key).first()
    if setting:
        setting.value = value
    else:
        setting = Setting(key=key, value=value)
        db.add(setting)


def is_password_reset_allowed(db: Session) -> bool:
    value = get_setting(db, "allow_password_resets", "0")
    return str(value) == "1"


def get_exam_duration_minutes(db: Session) -> int:
    value = get_setting(db, "exam_duration_minutes")
    try:
        return int(value) if value is not None else 30
    except ValueError:
        return 30


# --- Parsing helpers ---
def parse_word(file_path: str):
    doc = docx.Document(file_path)
    questions = []

    for para in doc.paragraphs:
        text = para.text.strip()
        if text.startswith("Q"):
            questions.append({"question": text, "type": "mcq"})

    return questions


def parse_pdf(file_path: str):
    questions = []

    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            for line in text.split("\n"):
                line = line.strip()
                if line.startswith("Q"):
                    questions.append({"question": line, "type": "mcq"})

    return questions


def score_answer(question: Question, submitted: str) -> Optional[int]:
    if not submitted:
        return 0

    max_marks = question.max_marks or 1

    if question.type == "mcq":
        correct = (question.correct_answer or "").strip().upper()
        return max_marks if submitted.strip().upper() == correct and correct else 0

    if question.type == "short":
        correct = (question.correct_answer or "").strip().lower()
        return max_marks if correct and submitted.strip().lower() == correct else 0

    # long/match/arrange are graded manually
    return None


def create_default_admin(db: Session):
    existing = db.query(User).filter(User.role == "admin").first()
    if existing:
        return

    admin = User(
        name="Admin",
        email="admin@example.com",
        password=get_password_hash("admin"),
        role="admin",
    )
    db.add(admin)
    db.commit()
    # Ensure a default exam duration exists
    set_setting(db, "exam_duration_minutes", "30")


app = FastAPI()
def ensure_schema():
    # Ensure missing columns are added when upgrading schema.
    with engine.begin() as conn:
        # Add exam_id and max_marks to questions if missing.
        info = conn.execute(text("PRAGMA table_info(questions)")).mappings().all()
        cols = [row["name"] for row in info]
        if "exam_id" not in cols:
            conn.execute(text("ALTER TABLE questions ADD COLUMN exam_id INTEGER"))
        if "max_marks" not in cols:
            conn.execute(text("ALTER TABLE questions ADD COLUMN max_marks INTEGER"))

        # Add created_by and metadata to exams if missing.
        info = conn.execute(text("PRAGMA table_info(exams)")).mappings().all()
        cols = [row["name"] for row in info]
        if "created_by" not in cols:
            conn.execute(text("ALTER TABLE exams ADD COLUMN created_by INTEGER"))
        if "course" not in cols:
            conn.execute(text("ALTER TABLE exams ADD COLUMN course TEXT"))
        if "subject" not in cols:
            conn.execute(text("ALTER TABLE exams ADD COLUMN subject TEXT"))
        if "code" not in cols:
            conn.execute(text("ALTER TABLE exams ADD COLUMN code TEXT"))
        if "start_at" not in cols:
            conn.execute(text("ALTER TABLE exams ADD COLUMN start_at TEXT"))
        if "end_at" not in cols:
            conn.execute(text("ALTER TABLE exams ADD COLUMN end_at TEXT"))
        if "published" not in cols:
            conn.execute(text("ALTER TABLE exams ADD COLUMN published INTEGER DEFAULT 0"))
        if "accepting_responses" not in cols:
            conn.execute(text("ALTER TABLE exams ADD COLUMN accepting_responses INTEGER DEFAULT 1"))

        # Ensure new columns have default values for existing rows.
        conn.execute(text("UPDATE exams SET published = 0 WHERE published IS NULL"))
        conn.execute(text("UPDATE exams SET accepting_responses = 1 WHERE accepting_responses IS NULL"))

        # Add student profile fields to users if missing.
        info = conn.execute(text("PRAGMA table_info(users)")).mappings().all()
        cols = [row["name"] for row in info]
        if "course" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN course TEXT"))
        if "programme" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN programme TEXT"))
        if "enrollment_no" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN enrollment_no TEXT"))

        # Add profile update request table if missing.
        info = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='profile_update_requests'"))
        if not info.fetchone():
            conn.execute(
                text(
                    """
                    CREATE TABLE profile_update_requests (
                      id INTEGER PRIMARY KEY,
                      student_id INTEGER NOT NULL,
                      new_name TEXT,
                      new_email TEXT,
                      new_course TEXT,
                      new_programme TEXT,
                      new_enrollment_no TEXT,
                      status TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      reviewed_at TEXT,
                      reviewed_by INTEGER
                    )
                    """
                )
            )

        # Add session_id to answers if missing.
        info = conn.execute(text("PRAGMA table_info(answers)")).mappings().all()
        cols = [row["name"] for row in info]
        if "session_id" not in cols:
            conn.execute(text("ALTER TABLE answers ADD COLUMN session_id INTEGER"))


def create_default_exam(db: Session):
    exam = db.query(Exam).filter(Exam.name == "Default Exam").first()
    if not exam:
        exam = Exam(
            name="Default Exam",
            course="General",
            subject="General",
            code="DEFAULT",
            duration_minutes=30,
            description="Default exam",
            start_at=datetime.utcnow().isoformat(),
            end_at=(datetime.utcnow() + timedelta(minutes=30)).isoformat(),
            published=1,
            accepting_responses=1,
        )
        db.add(exam)
        db.commit()
    # Ensure existing questions without an exam are attached to the default exam.
    for q in db.query(Question).filter(Question.exam_id.is_(None)).all():
        q.exam_id = exam.id
    db.commit()
    return exam


Base.metadata.create_all(bind=engine)
ensure_schema()

# create default admin if none exists
with SessionLocal() as db:
    create_default_admin(db)
    create_default_exam(db)


@app.get("/", response_class=HTMLResponse)
def landing(request: Request, user: Optional[User] = Depends(get_current_user)):
    # If already logged in, redirect to the appropriate dashboard.
    if user and user.role == "admin":
        return RedirectResponse(url="/admin/dashboard")
    if user and user.role == "student":
        return RedirectResponse(url="/student/exams")

    # Otherwise show a simple landing page with both student and admin login options.
    return templates.TemplateResponse("landing.html", {"request": request, "title": "QuizUP"})


# --- Admin routes ---
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_form(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request, "title": "Admin Login"})


@app.get("/admin/forgot", response_class=HTMLResponse)
def admin_forgot_password(request: Request, db: Session = Depends(get_db)):
    allowed = is_password_reset_allowed(db)
    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "title": "Forgot Password", "role": "admin", "allowed": allowed, "message": None},
    )


@app.post("/admin/forgot")
def admin_forgot_password_post(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    allowed = is_password_reset_allowed(db)
    message = None
    if not allowed:
        message = "Password reset is currently disabled. Contact an admin."
    else:
        user = db.query(User).filter(User.email == email, User.role == "admin").first()
        if user:
            user.password = get_password_hash("1234")
            db.commit()
            message = "Password reset: your password is now 1234. Please log in and change it."
        else:
            message = "No admin found with that email."

    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "title": "Forgot Password", "role": "admin", "allowed": allowed, "message": message},
    )


@app.post("/admin/login")
def admin_login(request: Request, response: Response, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.password) or user.role != "admin":
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "title": "Admin Login", "error": "Invalid credentials"},
        )

    token = create_access_token({"sub": str(user.id)})
    response = RedirectResponse(url="/admin/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response


@app.get("/admin/logout")
def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=303)
    response.delete_cookie("access_token")
    return response


@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    questions = db.query(Question).order_by(Question.id).all()
    duration = get_exam_duration_minutes(db)
    reset_allowed = is_password_reset_allowed(db)
    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "user": user,
            "title": "Admin Dashboard",
            "questions": questions,
            "exam_duration": duration,
            "password_reset_allowed": reset_allowed,
        },
    )


@app.post("/admin/settings")
def admin_settings_update(
    request: Request,
    duration: int = Form(...),
    allow_password_reset: Optional[str] = Form(None),
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    set_setting(db, "exam_duration_minutes", str(duration))
    set_setting(db, "allow_password_resets", "1" if allow_password_reset else "0")
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=303)


@app.post("/admin/upload")
def admin_upload(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    os.makedirs("uploads", exist_ok=True)
    file_path = os.path.join("uploads", file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    if file.filename.endswith(".docx"):
        questions = parse_word(file_path)
    elif file.filename.endswith(".pdf"):
        questions = parse_pdf(file_path)
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")

    for q in questions:
        new_q = Question(question=q["question"], type=q["type"])
        db.add(new_q)

    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=303)


@app.get("/admin/questions/new", response_class=HTMLResponse)
def admin_question_new(request: Request, user: User = Depends(get_current_admin)):
    return templates.TemplateResponse(
        "question_form.html",
        {"request": request, "user": user, "title": "Add Question", "action": "/admin/questions/new", "question": None},
    )


@app.post("/admin/questions/new")
def admin_question_create(
    request: Request,
    question: str = Form(...),
    type: str = Form(...),
    option_a: Optional[str] = Form(None),
    option_b: Optional[str] = Form(None),
    option_c: Optional[str] = Form(None),
    option_d: Optional[str] = Form(None),
    correct_answer: Optional[str] = Form(None),
    max_marks: int = Form(1),
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    q = Question(
        question=question,
        type=type,
        option_a=option_a,
        option_b=option_b,
        option_c=option_c,
        option_d=option_d,
        correct_answer=correct_answer,
        max_marks=max_marks,
    )
    db.add(q)
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=303)


@app.get("/admin/questions/{question_id}/edit", response_class=HTMLResponse)
def admin_question_edit(
    request: Request,
    question_id: int,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    question = db.query(Question).filter(Question.id == question_id).first()
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")

    return templates.TemplateResponse(
        "question_form.html",
        {"request": request, "user": user, "title": "Edit Question", "action": f"/admin/questions/{question_id}/edit", "question": question},
    )


@app.post("/admin/questions/{question_id}/edit")
def admin_question_update(
    question_id: int,
    request: Request,
    question: str = Form(...),
    type: str = Form(...),
    option_a: Optional[str] = Form(None),
    option_b: Optional[str] = Form(None),
    option_c: Optional[str] = Form(None),
    option_d: Optional[str] = Form(None),
    correct_answer: Optional[str] = Form(None),
    max_marks: int = Form(1),
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    q = db.query(Question).filter(Question.id == question_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Question not found")

    q.question = question
    q.type = type
    q.option_a = option_a
    q.option_b = option_b
    q.option_c = option_c
    q.option_d = option_d
    q.correct_answer = correct_answer
    q.max_marks = max_marks
    db.commit()

    return RedirectResponse(url="/admin/dashboard", status_code=303)


@app.post("/admin/questions/{question_id}/delete")
def admin_question_delete(
    question_id: int,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    q = db.query(Question).filter(Question.id == question_id).first()
    if q:
        db.delete(q)
        db.commit()

    return RedirectResponse(url="/admin/dashboard", status_code=303)


@app.get("/admin/submissions", response_class=HTMLResponse)
def admin_submissions(
    request: Request,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    answers = db.query(Answer).order_by(Answer.id.desc()).all()
    return templates.TemplateResponse(
        "submissions.html",
        {"request": request, "user": user, "title": "Submissions", "answers": answers},
    )


@app.post("/admin/submissions/{answer_id}/grade")
def admin_grade(
    answer_id: int,
    marks: int = Form(...),
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    ans = db.query(Answer).filter(Answer.id == answer_id).first()
    if not ans:
        raise HTTPException(status_code=404, detail="Answer not found")

    ans.marks = marks
    db.commit()
    return RedirectResponse(url="/admin/submissions", status_code=303)


@app.get("/admin/results", response_class=HTMLResponse)
def admin_results(
    request: Request,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    # Summary view for all students
    total_questions = db.query(Question).count()
    students = db.query(User).filter(User.role == "student").order_by(User.email).all()

    results = []
    for student in students:
        answers = db.query(Answer).filter(Answer.student_id == student.id).all()
        scored = sum((a.marks or 0) for a in answers if a.marks is not None)
        graded = sum(1 for a in answers if a.marks is not None)
        results.append(
            {
                "student": student,
                "scored": scored,
                "total": total_questions,
                "answered": len(answers),
                "pending": max(0, total_questions - graded),
            }
        )

    return templates.TemplateResponse(
        "admin_results.html",
        {"request": request, "user": user, "title": "Student Results", "results": results},
    )


@app.get("/admin/results/{student_id}", response_class=HTMLResponse)
def admin_results_detail(
    request: Request,
    student_id: int,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    student = get_user_by_id(db, student_id)
    if not student or student.role != "student":
        raise HTTPException(status_code=404, detail="Student not found")

    total_questions = db.query(Question).count()
    answers = db.query(Answer).filter(Answer.student_id == student.id).order_by(Answer.id).all()

    scored = sum((a.marks or 0) for a in answers if a.marks is not None)
    graded = sum(1 for a in answers if a.marks is not None)
    pending = max(0, total_questions - graded)

    return templates.TemplateResponse(
        "admin_student_results.html",
        {
            "request": request,
            "user": user,
            "title": f"Results for {student.name}",
            "student": student,
            "answers": answers,
            "total_questions": total_questions,
            "scored": scored,
            "pending": pending,
        },
    )


# --- Faculty routes ---
@app.get("/faculty/register", response_class=HTMLResponse)
def faculty_register_form(request: Request, user: Optional[User] = Depends(get_current_user)):
    return templates.TemplateResponse(
        "faculty_register.html", {"request": request, "title": "Faculty Register", "user": user}
    )


@app.post("/faculty/register")
def faculty_register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing = get_user_by_email(db, email)
    if existing:
        return templates.TemplateResponse(
            "faculty_register.html",
            {"request": request, "title": "Faculty Register", "error": "Email already registered"},
        )

    user = User(name=name, email=email, password=get_password_hash(password), role="faculty")
    db.add(user)
    db.commit()
    return RedirectResponse(url="/faculty/login", status_code=303)


@app.get("/faculty/login", response_class=HTMLResponse)
def faculty_login_form(request: Request, user: Optional[User] = Depends(get_current_user)):
    if user and user.role == "faculty":
        return RedirectResponse(url="/faculty/dashboard")
    return templates.TemplateResponse(
        "faculty_login.html", {"request": request, "title": "Faculty Login", "user": user}
    )


@app.get("/faculty/forgot", response_class=HTMLResponse)
def faculty_forgot_password(request: Request, db: Session = Depends(get_db)):
    allowed = is_password_reset_allowed(db)
    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "title": "Forgot Password", "role": "faculty", "allowed": allowed, "message": None},
    )


@app.post("/faculty/forgot")
def faculty_forgot_password_post(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    allowed = is_password_reset_allowed(db)
    message = None
    if not allowed:
        message = "Password reset is currently disabled. Contact an admin."
    else:
        user = db.query(User).filter(User.email == email, User.role == "faculty").first()
        if user:
            user.password = get_password_hash("1234")
            db.commit()
            message = "Password reset: your password is now 1234. Please log in and change it."
        else:
            message = "No faculty found with that email."

    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "title": "Forgot Password", "role": "faculty", "allowed": allowed, "message": message},
    )


@app.post("/faculty/login")
def faculty_login(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.password) or user.role != "faculty":
        return templates.TemplateResponse(
            "faculty_login.html",
            {"request": request, "title": "Faculty Login", "error": "Invalid credentials"},
        )

    token = create_access_token({"sub": str(user.id)})
    response = RedirectResponse(url="/faculty/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response


@app.get("/faculty/logout")
def faculty_logout():
    response = RedirectResponse(url="/faculty/login", status_code=303)
    response.delete_cookie("access_token")
    return response


@app.get("/faculty/dashboard", response_class=HTMLResponse)
def faculty_dashboard(
    request: Request,
    subject: Optional[str] = None,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    # List exams created by this faculty member. Optionally filter by subject.
    all_exams = db.query(Exam).filter(Exam.created_by == user.id).order_by(Exam.subject, Exam.name).all()
    subjects = sorted({e.subject for e in all_exams if e.subject})

    query = db.query(Exam).filter(Exam.created_by == user.id)
    if subject:
        query = query.filter(Exam.subject == subject)

    exams = query.order_by(Exam.subject, Exam.name).all()

    return templates.TemplateResponse(
        "faculty_dashboard.html",
        {
            "request": request,
            "user": user,
            "title": "Faculty Dashboard",
            "exams": exams,
            "subjects": subjects,
            "selected_subject": subject,
        },
    )


@app.get("/faculty/exams/new", response_class=HTMLResponse)
def faculty_exam_new(request: Request, user: User = Depends(get_current_faculty)):
    return templates.TemplateResponse(
        "exam_form.html",
        {"request": request, "user": user, "title": "Create Exam", "action": "/faculty/exams/new", "exam": None},
    )


@app.post("/faculty/exams/new")
def faculty_exam_create(
    request: Request,
    name: str = Form(...),
    course: Optional[str] = Form(None),
    subject: Optional[str] = Form(None),
    code: Optional[str] = Form(None),
    published: Optional[str] = Form(None),
    accepting_responses: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    duration: int = Form(...),
    start_at: Optional[str] = Form(None),
    end_at: Optional[str] = Form(None),
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = Exam(
        name=name,
        course=course,
        subject=subject,
        code=code,
        published=1 if published else 0,
        accepting_responses=1 if accepting_responses else 0,
        description=description,
        duration_minutes=duration,
        start_at=start_at,
        end_at=end_at,
        created_by=user.id,
    )
    db.add(exam)
    db.commit()
    return RedirectResponse(url="/faculty/dashboard", status_code=303)


@app.get("/faculty/exams/{exam_id}", response_class=HTMLResponse)
def faculty_exam_view(
    request: Request,
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    return templates.TemplateResponse(
        "faculty_exam_view.html",
        {"request": request, "user": user, "title": exam.name, "exam": exam},
    )


@app.post("/faculty/exams/{exam_id}/publish")
def faculty_exam_publish(
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    exam.published = 1
    exam.accepting_responses = 1
    db.commit()
    return RedirectResponse(url=f"/faculty/exams/{exam_id}", status_code=303)


@app.post("/faculty/exams/{exam_id}/unpublish")
def faculty_exam_unpublish(
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    exam.published = 0
    db.commit()
    return RedirectResponse(url=f"/faculty/exams/{exam_id}", status_code=303)


@app.post("/faculty/exams/{exam_id}/responses/enable")
def faculty_exam_enable_responses(
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    exam.accepting_responses = 1
    db.commit()
    return RedirectResponse(url=f"/faculty/exams/{exam_id}", status_code=303)


@app.post("/faculty/exams/{exam_id}/responses/disable")
def faculty_exam_disable_responses(
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    exam.accepting_responses = 0
    db.commit()
    return RedirectResponse(url=f"/faculty/exams/{exam_id}", status_code=303)


@app.get("/faculty/exams/{exam_id}/edit", response_class=HTMLResponse)
def faculty_exam_edit(
    request: Request,
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    return templates.TemplateResponse(
        "exam_form.html",
        {"request": request, "user": user, "title": f"Edit {exam.name}", "action": f"/faculty/exams/{exam_id}/edit", "exam": exam},
    )


@app.post("/faculty/exams/{exam_id}/edit")
def faculty_exam_update(
    request: Request,
    exam_id: int,
    name: str = Form(...),
    course: Optional[str] = Form(None),
    subject: Optional[str] = Form(None),
    code: Optional[str] = Form(None),
    published: Optional[str] = Form(None),
    accepting_responses: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    duration: int = Form(...),
    start_at: Optional[str] = Form(None),
    end_at: Optional[str] = Form(None),
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    exam.name = name
    exam.course = course
    exam.subject = subject
    exam.code = code
    exam.published = 1 if published else 0
    exam.accepting_responses = 1 if accepting_responses else 0
    exam.description = description
    exam.duration_minutes = duration
    exam.start_at = start_at
    exam.end_at = end_at

    db.commit()
    return RedirectResponse(url=f"/faculty/exams/{exam_id}", status_code=303)


@app.get("/faculty/exams/{exam_id}/export", response_class=Response)
def faculty_exam_export(
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    from fpdf import FPDF
    import io
    import zipfile

    sessions = db.query(ExamSession).filter(ExamSession.exam_id == exam.id).all()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for ses in sessions:
            student = db.query(User).filter(User.id == ses.student_id).first()
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 10, f"Student: {student.name} <{student.email}>", ln=1)
            pdf.cell(0, 10, f"Exam: {exam.name}", ln=1)
            pdf.cell(0, 10, f"Started: {ses.started_at}", ln=1)
            pdf.cell(0, 10, f"Submitted: {ses.submitted_at or 'N/A'}", ln=1)
            pdf.ln(4)
            answers = db.query(Answer).filter(Answer.session_id == ses.id).all()
            for a in answers:
                pdf.multi_cell(0, 6, f"Q: {a.question.question if a.question else '—'}")
                pdf.multi_cell(0, 6, f"A: {a.answer}")
                pdf.multi_cell(0, 6, f"Marks: {a.marks if a.marks is not None else '—'}")
                pdf.ln(2)

            fname = f"exam_{exam.id}_student_{student.email}.pdf"
            pdf_bytes = pdf.output(dest='S').encode('latin1')
            z.writestr(fname, pdf_bytes)

    buf.seek(0)
    return Response(
        content=buf.read(),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=exam_{exam.id}_answers.zip"},
    )


@app.post("/faculty/exams/{exam_id}/delete")
def faculty_exam_delete(
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if exam:
        db.query(Answer).filter(Answer.question_id.in_([q.id for q in exam.questions])).delete(synchronize_session=False)
        db.query(Question).filter(Question.exam_id == exam.id).delete(synchronize_session=False)
        db.query(ExamSession).filter(ExamSession.exam_id == exam.id).delete(synchronize_session=False)
        db.delete(exam)
        db.commit()
    return RedirectResponse(url="/faculty/dashboard", status_code=303)


@app.get("/faculty/exams/{exam_id}/questions/new", response_class=HTMLResponse)
def faculty_question_new(
    request: Request,
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    return templates.TemplateResponse(
        "question_form.html",
        {
            "request": request,
            "user": user,
            "title": f"Add Question to {exam.name}",
            "action": f"/faculty/exams/{exam_id}/questions/new",
            "question": None,
        },
    )


@app.post("/faculty/exams/{exam_id}/questions/new")
def faculty_question_create(
    request: Request,
    exam_id: int,
    question: str = Form(...),
    type: str = Form(...),
    option_a: Optional[str] = Form(None),
    option_b: Optional[str] = Form(None),
    option_c: Optional[str] = Form(None),
    option_d: Optional[str] = Form(None),
    correct_answer: Optional[str] = Form(None),
    max_marks: int = Form(1),
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    q = Question(
        exam_id=exam.id,
        question=question,
        type=type,
        option_a=option_a,
        option_b=option_b,
        option_c=option_c,
        option_d=option_d,
        correct_answer=correct_answer,
        max_marks=max_marks,
    )
    db.add(q)
    db.commit()
    return RedirectResponse(url=f"/faculty/exams/{exam_id}", status_code=303)


@app.get("/faculty/exams/{exam_id}/questions/{question_id}/edit", response_class=HTMLResponse)
def faculty_question_edit(
    request: Request,
    exam_id: int,
    question_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    question = db.query(Question).filter(Question.id == question_id, Question.exam_id == exam_id).first()
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")

    return templates.TemplateResponse(
        "question_form.html",
        {
            "request": request,
            "user": user,
            "title": f"Edit Question",
            "action": f"/faculty/exams/{exam_id}/questions/{question_id}/edit",
            "question": question,
        },
    )


@app.post("/faculty/exams/{exam_id}/questions/{question_id}/edit")
def faculty_question_update(
    exam_id: int,
    question_id: int,
    request: Request,
    question: str = Form(...),
    type: str = Form(...),
    option_a: Optional[str] = Form(None),
    option_b: Optional[str] = Form(None),
    option_c: Optional[str] = Form(None),
    option_d: Optional[str] = Form(None),
    correct_answer: Optional[str] = Form(None),
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    q = db.query(Question).filter(Question.id == question_id, Question.exam_id == exam_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Question not found")

    q.question = question
    q.type = type
    q.option_a = option_a
    q.option_b = option_b
    q.option_c = option_c
    q.option_d = option_d
    q.correct_answer = correct_answer
    q.max_marks = max_marks
    db.commit()

    return RedirectResponse(url=f"/faculty/exams/{exam_id}", status_code=303)


@app.post("/faculty/exams/{exam_id}/questions/{question_id}/delete")
def faculty_question_delete(
    exam_id: int,
    question_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if exam:
        q = db.query(Question).filter(Question.id == question_id, Question.exam_id == exam_id).first()
        if q:
            db.delete(q)
            db.commit()
    return RedirectResponse(url=f"/faculty/exams/{exam_id}", status_code=303)


@app.get("/faculty/exams/{exam_id}/submissions", response_class=HTMLResponse)
def faculty_exam_submissions(
    request: Request,
    exam_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    sessions = (
        db.query(ExamSession)
        .filter(ExamSession.exam_id == exam.id)
        .order_by(ExamSession.started_at.desc())
        .all()
    )

    # Precompute scores for each session
    session_info = []
    for ses in sessions:
        answers = db.query(Answer).filter(Answer.session_id == ses.id).all()
        score = sum((a.marks or 0) for a in answers if a.marks is not None)
        session_info.append({
            "session": ses,
            "student": db.query(User).filter(User.id == ses.student_id).first(),
            "score": score,
            "answers": answers,
        })

    return templates.TemplateResponse(
        "submissions.html",
        {
            "request": request,
            "user": user,
            "title": f"Submissions for {exam.name}",
            "exam": exam,
            "sessions": session_info,
        },
    )


@app.get("/faculty/exams/{exam_id}/sessions/{session_id}", response_class=HTMLResponse)
def faculty_exam_session_detail(
    request: Request,
    exam_id: int,
    session_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    session = db.query(ExamSession).filter(ExamSession.id == session_id, ExamSession.exam_id == exam.id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    student = db.query(User).filter(User.id == session.student_id).first()
    answers = db.query(Answer).filter(Answer.session_id == session.id).all()

    return templates.TemplateResponse(
        "faculty_session_detail.html",
        {
            "request": request,
            "user": user,
            "title": f"Session {session.id} - {student.name if student else 'Unknown'}",
            "exam": exam,
            "session": session,
            "student": student,
            "answers": answers,
        },
    )


@app.post("/faculty/exams/{exam_id}/sessions/{session_id}/reset")
def faculty_exam_session_reset(
    exam_id: int,
    session_id: int,
    user: User = Depends(get_current_faculty),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id, Exam.created_by == user.id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    session = db.query(ExamSession).filter(ExamSession.id == session_id, ExamSession.exam_id == exam.id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Remove previous answers and allow the student to retake.
    db.query(Answer).filter(Answer.session_id == session.id).delete(synchronize_session=False)
    session.started_at = datetime.utcnow().isoformat()
    session.submitted_at = None
    session.locked = 0
    db.commit()

    return RedirectResponse(url=f"/faculty/exams/{exam_id}/submissions", status_code=303)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    users = db.query(User).filter(User.role != "admin").order_by(User.role, User.email).all()
    return templates.TemplateResponse(
        "admin_users.html", {"request": request, "user": user, "title": "User Management", "users": users}
    )


@app.get("/admin/profile-requests", response_class=HTMLResponse)
def admin_profile_requests(
    request: Request,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    requests = db.query(ProfileUpdateRequest).order_by(ProfileUpdateRequest.created_at.desc()).all()
    return templates.TemplateResponse(
        "admin_profile_requests.html",
        {"request": request, "user": user, "title": "Profile Update Requests", "requests": requests},
    )


@app.post("/admin/profile-requests/{req_id}/approve")
def admin_profile_request_approve(
    req_id: int,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    req = db.query(ProfileUpdateRequest).filter(ProfileUpdateRequest.id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")

    student = db.query(User).filter(User.id == req.student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    # Apply requested changes
    if req.new_name:
        student.name = req.new_name
    if req.new_email:
        student.email = req.new_email
    if req.new_course:
        student.course = req.new_course
    if req.new_programme:
        student.programme = req.new_programme
    if req.new_enrollment_no:
        student.enrollment_no = req.new_enrollment_no

    req.status = "approved"
    req.reviewed_at = datetime.utcnow().isoformat()
    req.reviewed_by = user.id

    db.commit()
    return RedirectResponse(url="/admin/profile-requests", status_code=303)


@app.post("/admin/profile-requests/{req_id}/reject")
def admin_profile_request_reject(
    req_id: int,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    req = db.query(ProfileUpdateRequest).filter(ProfileUpdateRequest.id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")

    req.status = "rejected"
    req.reviewed_at = datetime.utcnow().isoformat()
    req.reviewed_by = user.id
    db.commit()
    return RedirectResponse(url="/admin/profile-requests", status_code=303)


@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(
    user_id: int,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.id == user_id, User.role != "admin").first()
    if target:
        # cascade delete their sessions and answers
        db.query(Answer).filter(Answer.student_id == target.id).delete(synchronize_session=False)
        db.query(ExamSession).filter(ExamSession.student_id == target.id).delete(synchronize_session=False)
        db.delete(target)
        db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)


@app.post("/admin/factory-reset")
def admin_factory_reset(
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    # Delete everything except admin user(s)
    db.query(Answer).delete(synchronize_session=False)
    db.query(ExamSession).delete(synchronize_session=False)
    db.query(Question).delete(synchronize_session=False)
    db.query(Exam).delete(synchronize_session=False)
    db.query(User).filter(User.role != "admin").delete(synchronize_session=False)
    db.query(Setting).delete(synchronize_session=False)
    db.commit()
    # Recreate default exam and admin settings
    create_default_admin(db)
    create_default_exam(db)
    return RedirectResponse(url="/admin/dashboard", status_code=303)


@app.get("/admin/export/questions", response_class=Response)
def admin_export_questions(
    request: Request,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    # Export questions to CSV. Optional filters include subject and course.
    import csv
    import io

    subject = request.query_params.get("subject")
    course = request.query_params.get("course")

    query = db.query(Question).join(Exam, Question.exam_id == Exam.id)
    if subject:
        query = query.filter(Exam.subject.ilike(f"%{subject}%"))
    if course:
        query = query.filter(Exam.course.ilike(f"%{course}%"))

    questions = query.order_by(Exam.subject, Exam.course, Question.id).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Exam ID",
        "Exam Name",
        "Course",
        "Subject",
        "Question ID",
        "Question",
        "Type",
        "Option A",
        "Option B",
        "Option C",
        "Option D",
        "Correct Answer",
        "Max Marks",
    ])

    for q in questions:
        exam = q.exam
        writer.writerow([
            exam.id if exam else "",
            exam.name if exam else "",
            exam.course if exam else "",
            exam.subject if exam else "",
            q.id,
            q.question,
            q.type,
            q.option_a or "",
            q.option_b or "",
            q.option_c or "",
            q.option_d or "",
            q.correct_answer or "",
            q.max_marks or "",
        ])

    content = buf.getvalue().encode("utf-8")
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=questions_export.csv"},
    )


@app.get("/admin/export/answers", response_class=Response)
def admin_export_answers(
    request: Request,
    user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    # Generate a ZIP containing per-student PDF answer sheets.
    from fpdf import FPDF
    import io
    import zipfile

    subject = request.query_params.get("subject")
    course = request.query_params.get("course")
    filter_term = request.query_params.get("filter")
    sort_key = request.query_params.get("sort")

    students_query = db.query(User).filter(User.role == "student")
    if filter_term:
        like_term = f"%{filter_term}%"
        students_query = students_query.filter(
            (User.name.ilike(like_term))
            | (User.email.ilike(like_term))
            | (User.enrollment_no.ilike(like_term))
        )

    if sort_key == "name":
        students_query = students_query.order_by(User.name)
    elif sort_key == "email":
        students_query = students_query.order_by(User.email)
    elif sort_key == "enrollment":
        students_query = students_query.order_by(User.enrollment_no)
    else:
        students_query = students_query.order_by(User.email)

    students = students_query.all()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for s in students:
            session_query = db.query(ExamSession).join(Exam, ExamSession.exam_id == Exam.id).filter(ExamSession.student_id == s.id)
            if subject:
                session_query = session_query.filter(Exam.subject.ilike(f"%{subject}%"))
            if course:
                session_query = session_query.filter(Exam.course.ilike(f"%{course}%"))

            sessions = session_query.all()
            if not sessions:
                continue

            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 10, f"Student: {s.name} <{s.email}>", ln=1)
            pdf.cell(0, 10, "Answers:", ln=1)

            for ses in sessions:
                pdf.cell(0, 8, f"Exam: {ses.exam.name}", ln=1)
                pdf.cell(0, 8, f"Started: {ses.started_at}", ln=1)
                pdf.cell(0, 8, f"Submitted: {ses.submitted_at or 'N/A'}", ln=1)
                answers = db.query(Answer).filter(Answer.session_id == ses.id).all()
                for a in answers:
                    pdf.multi_cell(0, 6, f"Q: {a.question.question if a.question else '—'}")
                    pdf.multi_cell(0, 6, f"A: {a.answer}")
                    pdf.multi_cell(0, 6, f"Marks: {a.marks if a.marks is not None else '—'}")
                    pdf.ln(1)
                pdf.ln(2)

            pdf_bytes = pdf.output(dest='S').encode('latin1')
            z.writestr(f"answers_{s.email}.pdf", pdf_bytes)

    buf.seek(0)
    return Response(
        content=buf.read(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=students_answers.zip"},
    )


# --- Student routes ---
@app.get("/student/register", response_class=HTMLResponse)
def student_register_form(request: Request, user: Optional[User] = Depends(get_current_user)):
    return templates.TemplateResponse(
        "student_register.html", {"request": request, "title": "Student Register", "user": user}
    )


@app.post("/student/register")
def student_register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    course: Optional[str] = Form(None),
    programme: Optional[str] = Form(None),
    enrollment_no: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    existing = get_user_by_email(db, email)
    if existing:
        return templates.TemplateResponse(
            "student_register.html",
            {"request": request, "title": "Student Register", "error": "Email already registered"},
        )

    user = User(
        name=name,
        email=email,
        password=get_password_hash(password),
        role="student",
        course=course,
        programme=programme,
        enrollment_no=enrollment_no,
    )
    db.add(user)
    db.commit()
    return RedirectResponse(url="/student/login", status_code=303)


@app.get("/student/login", response_class=HTMLResponse)
def student_login_form(request: Request, user: Optional[User] = Depends(get_current_user)):
    if user and user.role == "student":
        return RedirectResponse(url="/student/exams")
    return templates.TemplateResponse(
        "student_login.html", {"request": request, "title": "Student Login", "user": user}
    )


@app.get("/student/forgot", response_class=HTMLResponse)
def student_forgot_password(request: Request, db: Session = Depends(get_db)):
    allowed = is_password_reset_allowed(db)
    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "title": "Forgot Password", "role": "student", "allowed": allowed, "message": None},
    )


@app.post("/student/forgot")
def student_forgot_password_post(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    allowed = is_password_reset_allowed(db)
    message = None
    if not allowed:
        message = "Password reset is currently disabled. Contact an admin."
    else:
        user = db.query(User).filter(User.email == email, User.role == "student").first()
        if user:
            user.password = get_password_hash("1234")
            db.commit()
            message = "Password reset: your password is now 1234. Please log in and change it."
        else:
            message = "No student found with that email."

    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "title": "Forgot Password", "role": "student", "allowed": allowed, "message": message},
    )


@app.post("/student/login")
def student_login(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.password) or user.role != "student":
        return templates.TemplateResponse(
            "student_login.html",
            {"request": request, "title": "Student Login", "error": "Invalid credentials"},
        )

    token = create_access_token({"sub": str(user.id)})
    response = RedirectResponse(url="/student/exams", status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response


@app.get("/change-password", response_class=HTMLResponse)
def change_password_form(request: Request, user: Optional[User] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/student/login")
    return templates.TemplateResponse(
        "change_password.html",
        {"request": request, "title": "Change Password", "user": user, "message": None},
    )


@app.post("/change-password")
def change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    if new_password != confirm_password:
        return templates.TemplateResponse(
            "change_password.html",
            {"request": request, "title": "Change Password", "user": user, "message": "New passwords do not match."},
        )

    if not verify_password(old_password, user.password):
        return templates.TemplateResponse(
            "change_password.html",
            {"request": request, "title": "Change Password", "user": user, "message": "Old password is incorrect."},
        )

    user.password = get_password_hash(new_password)
    db.commit()

    return templates.TemplateResponse(
        "change_password.html",
        {"request": request, "title": "Change Password", "user": user, "message": "Password updated successfully."},
    )


@app.get("/student/logout")
def student_logout():
    response = RedirectResponse(url="/student/login", status_code=303)
    response.delete_cookie("access_token")
    return response


@app.get("/student/exams", response_class=HTMLResponse)
def student_exams(
    request: Request,
    subject: Optional[str] = None,
    error: Optional[str] = None,
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow().isoformat()
    base_query = (
        db.query(Exam)
        .filter(Exam.published == 1)
        .filter((Exam.start_at.is_(None)) | (Exam.start_at <= now))
        .filter((Exam.end_at.is_(None)) | (Exam.end_at >= now))
    )

    # Gather available subjects for filtering
    all_exams = base_query.order_by(Exam.subject, Exam.name).all()
    subjects = sorted({e.subject for e in all_exams if e.subject})

    if subject:
        base_query = base_query.filter(Exam.subject == subject)

    exams = base_query.order_by(Exam.subject, Exam.name).all()

    return templates.TemplateResponse(
        "student_exams.html",
        {
            "request": request,
            "user": user,
            "title": "Exams",
            "exams": exams,
            "subjects": subjects,
            "selected_subject": subject,
            "error": error,
        },
    )


@app.get("/student/exams/{exam_id}", response_class=HTMLResponse)
def student_exam_overview(
    request: Request,
    exam_id: int,
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    return RedirectResponse(url=f"/student/exams/{exam.id}/start", status_code=303)


@app.get("/student/exams/{exam_id}/start", response_class=HTMLResponse)
def student_exam_start(
    request: Request,
    exam_id: int,
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    now = datetime.utcnow()
    if exam.start_at:
        try:
            start_time = datetime.fromisoformat(exam.start_at)
            if now < start_time:
                return student_exams(
                    request,
                    user=user,
                    db=db,
                    subject=None,
                    error=f"This exam is not available until {exam.start_at} UTC.",
                )
        except ValueError:
            pass

    if exam.end_at:
        try:
            end_time = datetime.fromisoformat(exam.end_at)
            if now > end_time:
                return student_exams(
                    request,
                    user=user,
                    db=db,
                    subject=None,
                    error=f"This exam window has closed (ended at {exam.end_at} UTC).",
                )
        except ValueError:
            pass

    # Resume an existing session if it is still active.
    existing = (
        db.query(ExamSession)
        .filter(ExamSession.student_id == user.id)
        .filter(ExamSession.exam_id == exam.id)
        .order_by(ExamSession.id.desc())
        .first()
    )

    if existing:
        started = datetime.fromisoformat(existing.started_at)
        ends_at = started + timedelta(minutes=exam.duration_minutes)
        if exam.end_at:
            try:
                window_end = datetime.fromisoformat(exam.end_at)
                if window_end < ends_at:
                    ends_at = window_end
            except ValueError:
                pass

        if not existing.locked and datetime.utcnow() < ends_at:
            return RedirectResponse(url=f"/student/exams/{exam.id}/take/{existing.id}", status_code=303)

    # If the exam has a paper code, prompt for it before starting.
    if exam.code:
        return templates.TemplateResponse(
            "student_exam_code.html",
            {
                "request": request,
                "user": user,
                "title": f"Enter code for {exam.name}",
                "exam": exam,
                "error": None,
            },
        )

    return _start_student_session(exam, user, db)


@app.post("/student/exams/{exam_id}/start")
def student_exam_start_post(
    request: Request,
    exam_id: int,
    code: Optional[str] = Form(None),
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    if exam.code and code != exam.code:
        return templates.TemplateResponse(
            "student_exam_code.html",
            {
                "request": request,
                "user": user,
                "title": f"Enter code for {exam.name}",
                "exam": exam,
                "error": "Incorrect paper code. Please try again.",
            },
        )

    return _start_student_session(exam, user, db)


def _start_student_session(exam: Exam, user: User, db: Session):
    # Resume an existing session if it is still active.
    existing = (
        db.query(ExamSession)
        .filter(ExamSession.student_id == user.id)
        .filter(ExamSession.exam_id == exam.id)
        .order_by(ExamSession.id.desc())
        .first()
    )

    if existing:
        started = datetime.fromisoformat(existing.started_at)
        ends_at = started + timedelta(minutes=exam.duration_minutes)
        if exam.end_at:
            try:
                window_end = datetime.fromisoformat(exam.end_at)
                if window_end < ends_at:
                    ends_at = window_end
            except ValueError:
                pass

        if not existing.locked and datetime.utcnow() < ends_at:
            return RedirectResponse(url=f"/student/exams/{exam.id}/take/{existing.id}", status_code=303)

    # Create a new session for the student
    session = ExamSession(
        student_id=user.id,
        exam_id=exam.id,
        started_at=datetime.utcnow().isoformat(),
    )
    db.add(session)
    db.commit()

    return RedirectResponse(url=f"/student/exams/{exam.id}/take/{session.id}", status_code=303)


@app.get("/student/exams/{exam_id}/take/{session_id}", response_class=HTMLResponse)
def student_exam_take(
    request: Request,
    exam_id: int,
    session_id: int,
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id).first()
    session = db.query(ExamSession).filter(ExamSession.id == session_id, ExamSession.student_id == user.id).first()

    if not exam or not session:
        raise HTTPException(status_code=404, detail="Exam/session not found")

    # Determine exam end time and remaining duration
    started = datetime.fromisoformat(session.started_at)
    ends_at = started + timedelta(minutes=exam.duration_minutes)
    # Cap the session end at the exam window end, if configured.
    if exam.end_at:
        try:
            window_end = datetime.fromisoformat(exam.end_at)
            if window_end < ends_at:
                ends_at = window_end
        except ValueError:
            pass

    now = datetime.utcnow()
    remaining_seconds = max(0, int((ends_at - now).total_seconds()))
    responses_allowed = bool(exam.accepting_responses)
    locked = session.locked or remaining_seconds <= 0 or not responses_allowed

    if (remaining_seconds <= 0 or not responses_allowed) and not session.locked:
        session.locked = 1
        session.submitted_at = datetime.utcnow().isoformat()
        db.commit()

    # Load existing answers for this session
    answers = {
        a.question_id: a.answer
        for a in db.query(Answer).filter(Answer.session_id == session.id).all()
    }

    return templates.TemplateResponse(
        "student_exam_take.html",
        {
            "request": request,
            "user": user,
            "title": exam.name,
            "exam": exam,
            "session": session,
            "locked": locked,
            "remaining_seconds": remaining_seconds,
            "responses_allowed": responses_allowed,
            "questions": exam.questions,
            "answers": answers,
        },
    )


@app.post("/student/exams/{exam_id}/take/{session_id}")
async def student_submit_exam(
    request: Request,
    exam_id: int,
    session_id: int,
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    exam = db.query(Exam).filter(Exam.id == exam_id).first()
    session = db.query(ExamSession).filter(ExamSession.id == session_id, ExamSession.student_id == user.id).first()
    if not exam or not session:
        raise HTTPException(status_code=404, detail="Exam/session not found")

    started = datetime.fromisoformat(session.started_at)
    ends_at = started + timedelta(minutes=exam.duration_minutes)
    if exam.end_at:
        try:
            window_end = datetime.fromisoformat(exam.end_at)
            if window_end < ends_at:
                ends_at = window_end
        except ValueError:
            pass

    now = datetime.utcnow()
    responses_allowed = bool(exam.accepting_responses)

    locked = session.locked or now >= ends_at or not responses_allowed

    if not responses_allowed:
        # If the exam is not accepting responses, ensure session is locked and show results.
        session.locked = 1
        session.submitted_at = session.submitted_at or datetime.utcnow().isoformat()
        db.commit()
        return RedirectResponse(url=f"/student/results/{session.id}", status_code=303)

    form = await request.form()
    force_lock = form.get("force_lock") == "1"
    if force_lock:
        locked = True

    answers: Dict[int, str] = {}
    for key, value in form.items():
        if key.startswith("q_"):
            try:
                qid = int(key.replace("q_", ""))
                answers[qid] = value
            except ValueError:
                continue

    total_score = 0
    total_possible = 0

    # Auto-lock if time is up
    if now >= ends_at:
        locked = True

    for qid, submitted in answers.items():
        question = db.query(Question).filter(Question.id == qid, Question.exam_id == exam_id).first()
        if not question:
            continue

        score = score_answer(question, submitted)
        if score is not None:
            total_score += score
            total_possible += 1

        existing = (
            db.query(Answer)
            .filter(Answer.session_id == session.id)
            .filter(Answer.question_id == qid)
            .first()
        )

        if existing:
            existing.answer = submitted
            existing.marks = score
        else:
            db.add(
                Answer(
                    student_id=user.id,
                    question_id=qid,
                    session_id=session.id,
                    answer=submitted,
                    marks=score,
                )
            )

    session.locked = 1
    session.submitted_at = datetime.utcnow().isoformat()
    db.commit()

    return RedirectResponse(url=f"/student/results/{session.id}", status_code=303)


@app.get("/student/results", response_class=HTMLResponse)
def student_results(
    request: Request,
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    sessions = (
        db.query(ExamSession)
        .filter(ExamSession.student_id == user.id)
        .order_by(ExamSession.id.desc())
        .all()
    )

    results = []
    for ses in sessions:
        answers = db.query(Answer).filter(Answer.session_id == ses.id).all()
        total = len(answers)
        scored = sum((a.marks or 0) for a in answers if a.marks is not None)
        results.append({"session": ses, "score": scored, "total": total})

    return templates.TemplateResponse(
        "student_results_dashboard.html",
        {"request": request, "user": user, "title": "Results", "sessions": results},
    )


@app.get("/student/results/{session_id}", response_class=HTMLResponse)
def student_results_detail(
    request: Request,
    session_id: int,
    user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    session = db.query(ExamSession).filter(ExamSession.id == session_id, ExamSession.student_id == user.id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Result not found")

    answers = db.query(Answer).filter(Answer.session_id == session.id).all()
    total = len(answers)
    scored = sum((a.marks or 0) for a in answers if a.marks is not None)

    return templates.TemplateResponse(
        "student_session_results.html",
        {"request": request, "user": user, "title": "Result", "session": session, "answers": answers, "score": scored, "total": total},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


