from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form, Body, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, EmailStr, Field  
from pdf2image import convert_from_bytes
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from PIL import Image
from decimal import Decimal
from calendar import month_name
from collections import defaultdict
from typing import Annotated
import calendar
import mysql.connector
import bcrypt
import traceback
import pytesseract
import io
import re
import os
from dotenv import load_dotenv
import httpx

# Tesseract path
pytesseract.pytesseract.tesseract_cmd = "/usr/bin/tesseract"
POPPLER_PATH = None

app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://frontend-nu-azure-26.vercel.app"],  # Adjust as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MySQL configuration
db_config = {
    "host": "turntable.proxy.rlwy.net",
    "user": "root",
    "password": "lNKLKFIqVIFvAmiJkDJYpKHyFAagyyhJ",
    "database": "payslip",
    "port": 19999
}

load_dotenv()

# DeepSeek API Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

# API Key Security
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

# Models
class PayrollProfile(BaseModel):
    baseSalaryPerHour: float
    sssDeduction: float
    pagibigDeduction: float
    philhealthDeduction: float
    taxDeduction: float
    employment_type: str = "regular"
    leaveCredits: Optional[float] = 0.0 
    bonuses: list
    bonusOther: dict
    loans: list
    loanOther: dict

class Loan(BaseModel):
    name: str
    amount: float
    duration: int
    start_month: str


class UserProfile(BaseModel):
    full_name: str
    username: str
    email: EmailStr
    password: str = ""


class LoginData(BaseModel):
    username: str
    password: str

class DTRDayEntry(BaseModel):
    day: int
    am_arrival: str
    am_departure: str
    pm_arrival: str
    pm_departure: str
    undertime_hours: int
    undertime_minutes: int

class SalaryRequest(BaseModel):
    username: str
    month_str: str  


class DeductionItem(BaseModel):
    label: str
    amount: float

class PayslipResponse(BaseModel):
    fullName: str
    period: str
    totalHours: float
    ratePerHour: float
    grossIncome: float
    deductions: List[DeductionItem]

class MonthEntry(BaseModel):
    month: str
    year: int

class MonthSelection(BaseModel):
    username: str
    selected_months: List[MonthEntry]

class RecordOut(BaseModel):
    month: str
    year: int
    dtr_pdf_url: str
    payslip_pdf_url: Optional[str]
    payroll_report_pdf_url: Optional[str]

    class Config:
        orm_mode = True

class InsightRequest(BaseModel):
    payslip_data: dict
    analysis_type: Optional[str] = "standard"
    language: Optional[str] = "en"

class InsightResponse(BaseModel):
    insights: str
    model: str
    tokens_used: int

# Database initialization (run this once)
def initialize_database():
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Create tables if they don't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS dtrs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            employee_name VARCHAR(255) NOT NULL,
            month VARCHAR(100) NOT NULL,
            working_hours VARCHAR(255),
            verified_by VARCHAR(255),
            position VARCHAR(255),
            total_time VARCHAR(255),
            status VARCHAR(50) DEFAULT 'pending',
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed_at TIMESTAMP NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS dtr_days (
            id INT AUTO_INCREMENT PRIMARY KEY,
            dtr_id INT NOT NULL,
            day INT NOT NULL,
            am_arrival VARCHAR(20),
            am_departure VARCHAR(20),
            pm_arrival VARCHAR(20),
            pm_departure VARCHAR(20),
            undertime_hours INT DEFAULT 0,
            undertime_minutes INT DEFAULT 0,
            FOREIGN KEY (dtr_id) REFERENCES dtrs(id) ON DELETE CASCADE
        )
                       
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS payslips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            dtr_id INT,
            month VARCHAR(100) NOT NULL,
            year INT NOT NULL,  # Ensure this column exists
            working_days INT,
            days_present INT,
            days_absent INT,
            leave_used INT,
            gross_income DECIMAL(10,2),
            total_deductions DECIMAL(10,2),
            net_income DECIMAL(10,2),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (dtr_id) REFERENCES dtrs(id) ON DELETE SET NULL
        )
        """)
        connection.commit()
        print("Database tables initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


# Call this function when the application starts
initialize_database()

@app.post("/register")
def register_user(user: UserProfile):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        cursor.execute("SELECT id FROM users WHERE email = %s OR username = %s", (user.email, user.username))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email or username already exists")

        hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())

        cursor.execute("""
            INSERT INTO users (full_name, email, username, password_hash)
            VALUES (%s, %s, %s, %s)
        """, (user.full_name, user.email, user.username, hashed_password.decode('utf-8')))

        cursor.execute("SELECT id FROM users WHERE username = %s", (user.username,))
        user_id = cursor.fetchone()[0]

        cursor.execute("""
            INSERT INTO employee_profiles (
                user_id, employee_name, employment_type, base_salary_hour,
                philhealth_deduction, tax_deduction
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            user_id, user.full_name, "regular", 0.0, 0.0, 0.0
        ))

        connection.commit()
        return {"message": "User registered successfully"}
    except Exception as err:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(err)}")
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

# Login endpoint
@app.post("/login")
def login(user: LoginData):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT users.id, users.full_name, users.email, users.username, users.password_hash,
                   employee_profiles.employee_name, employee_profiles.employment_type,
                   employee_profiles.base_salary_hour
            FROM users
            LEFT JOIN employee_profiles ON users.id = employee_profiles.user_id
            WHERE users.username = %s
        """, (user.username,))
        
        result = cursor.fetchone()
        if result and bcrypt.checkpw(user.password.encode('utf-8'), result["password_hash"].encode('utf-8')):
            return {
                "message": "Login successful",
                "user": {
                    "id": result["id"],
                    "full_name": result["full_name"],
                    "username": result["username"],
                    "email": result["email"],
                    "employee_name": result.get("employee_name"),
                    "employment_type": result.get("employment_type"),
                    "base_salary_hour": result.get("base_salary_hour")
                }
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid username or password")
    except Exception as err:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Login failed: {str(err)}")
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

#fetch profile      
@app.get("/api/user/profile")
def get_user_profile(username: str = Query(...)):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Get basic user info
        cursor.execute("""
            SELECT id, full_name, username, email 
            FROM users 
            WHERE username = %s
            LIMIT 1
        """, (username,))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_id = user["id"]

        # Get payroll profile with proper null handling
        payroll_defaults = {
            "employment_type": "regular",
            "baseSalaryPerHour": 0.0,
            "gsisDeduction": 0.0,
            "philhealthDeduction": 0.0,
            "taxDeduction": 0.0,
            "leaveCredits": 0.0
        }
        
        cursor.execute("""
            SELECT 
                IFNULL(employment_type, %s) AS employment_type,
                IFNULL(salary_grade, %s) AS salaryGrade,
                IFNULL(base_monthly_salary, %s) AS baseMonthlySalary,
                IFNULL(base_salary_hour, %s) AS baseSalaryPerHour,
                IFNULL(gsis_deduction, %s) AS gsisDeduction,
                IFNULL(philhealth_deduction, %s) AS philhealthDeduction,
                IFNULL(tax_deduction, %s) AS taxDeduction,
                IFNULL(leave_credits, %s) AS leaveCredits
            FROM employee_profiles 
            WHERE user_id = %s
        """, (
            payroll_defaults["employment_type"],
            '12',  # default salaryGrade
            0,     # default baseMonthlySalary
            payroll_defaults["baseSalaryPerHour"],
            payroll_defaults["gsisDeduction"],
            payroll_defaults["philhealthDeduction"],
            payroll_defaults["taxDeduction"],
            payroll_defaults["leaveCredits"],
            user_id
        ))
        payroll = cursor.fetchone() or payroll_defaults

        # Get bonuses - ensure consistent structure
        cursor.execute("""
            SELECT 
            id,
            IFNULL(bonus_type, '') AS bonus_type,
            IFNULL(bonus_name, '') AS bonus_name,
            IFNULL(amount, 0) AS amount,
            IFNULL(frequency, 'monthly') AS frequency,
            DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') AS created_at
        FROM employee_bonuses
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))
        bonuses = cursor.fetchall()

        # Get loans - ensure consistent structure
        cursor.execute("""
              SELECT 
                    id,
                    IFNULL(loan_type, '') AS loan_type,
                    IFNULL(loan_name, '') AS loan_name,
                    IFNULL(amount, 0) AS amount,
                    IFNULL(start_month, '') AS start_month,
                    IFNULL(start_year, '') AS start_year,
                    IFNULL(duration_months, 0) AS duration_months,
                    CAST(IFNULL(balance, 0) AS DECIMAL(10,2)) AS balance,
                    DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') AS created_at
                FROM employee_loans
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (user_id,))
        loans = cursor.fetchall()

        return {
            "user": {
                "full_name": user["full_name"],
                "username": user["username"],
                "email": user["email"]
            },
            "payrollProfile": payroll,
            "bonuses": bonuses,
            "loans": loans,
            "status": "success",
            "timestamp": datetime.now().isoformat()
        }

    except Exception as err:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Fetch profile failed",
                "error": str(err),
                "status": "error"
            }
        )

    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

# PUT to update or insert payroll profile including leaveCredits
@app.put("/api/user/profile")
def update_user_profile(data: dict = Body(...)):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Get user_id
        cursor.execute("SELECT id FROM users WHERE username = %s", (data["username"],))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user_id = user[0]

        # Update users table
        cursor.execute("""
            UPDATE users SET full_name = %s, email = %s
            WHERE username = %s
        """, (data["full_name"], data["email"], data["username"]))

        # Extract nested payrollProfile
        payroll = data.get("payrollProfile", {})

        # Extract grade and salary values
        salary_grade = payroll.get("salaryGrade")
        base_monthly_salary = payroll.get("baseMonthlySalary")
        base_salary_hour = payroll.get("baseSalaryPerHour", 0.0)

        # Check if payroll profile exists
        cursor.execute("""
            SELECT id FROM employee_profiles WHERE user_id = %s
        """, (user_id,))
        existing_profile = cursor.fetchone()

        if existing_profile:
            cursor.execute("""
                UPDATE employee_profiles 
                SET employment_type = %s, salary_grade = %s,
                    base_monthly_salary = %s, base_salary_hour = %s,
                    gsis_deduction = %s, philhealth_deduction = %s, 
                    tax_deduction = %s, leave_credits = %s
                WHERE id = %s
            """, (
                payroll.get("employment_type", "regular"),
                salary_grade,
                base_monthly_salary,
                base_salary_hour,
                payroll.get("gsisDeduction", 0.0),
                payroll.get("philhealthDeduction", 0.0),
                payroll.get("taxDeduction", 0.0),
                payroll.get("leaveCredits", 0.0),
                existing_profile[0]
            ))
        else:
            cursor.execute("""
                INSERT INTO employee_profiles (
                    user_id, employment_type, salary_grade, 
                    base_monthly_salary, base_salary_hour, 
                    gsis_deduction, philhealth_deduction, 
                    tax_deduction, leave_credits
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id,
                payroll.get("employment_type", "regular"),
                salary_grade,
                base_monthly_salary,
                base_salary_hour,
                payroll.get("gsisDeduction", 0.0),
                payroll.get("philhealthDeduction", 0.0),
                payroll.get("taxDeduction", 0.0),
                payroll.get("leaveCredits", 0.0)
            ))

        # Password update
        if data.get("password"):
            hashed = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE users SET password_hash = %s WHERE username = %s", 
                           (hashed, data["username"]))

        # Clear and insert bonuses
        cursor.execute("DELETE FROM employee_bonuses WHERE user_id = %s", (user_id,))
        bonuses = payroll.get("bonuses", [])
        bonus_other = payroll.get("bonusOther", {})

        for bonus in bonuses:
            if bonus.get("name") and bonus.get("amount") is not None:
                cursor.execute("""
                    INSERT INTO employee_bonuses 
                    (user_id, bonus_type, bonus_name, amount, frequency)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    user_id,
                    bonus.get("type", ""),
                    bonus.get("name", ""),
                    float(bonus.get("amount", 0.0)),
                    bonus.get("frequency", "yearly")
                ))

        if bonus_other and bonus_other.get("name"):
            cursor.execute("""
                INSERT INTO employee_bonuses 
                (user_id, bonus_type, bonus_name, amount, frequency)
                VALUES (%s, 'other', %s, %s, %s)
            """, (
                user_id,
                bonus_other.get("name"),
                float(bonus_other.get("amount", 0.0)),
                bonus_other.get("frequency", "yearly")
            ))

        # Clear and insert loans
        cursor.execute("DELETE FROM employee_loans WHERE user_id = %s", (user_id,))
        loans = payroll.get("loans", [])
        loan_other = payroll.get("loanOther", {})

        for loan in loans:
            if loan.get("name") and loan.get("amount") is not None:
                loan_amount = float(loan.get("amount", 0.0))
                cursor.execute("""
                    INSERT INTO employee_loans (
                        user_id, loan_type, loan_name, amount, 
                        start_month, start_year, duration_months, balance
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    user_id,
                    loan.get("type", ""),
                    loan.get("name", ""),
                    loan_amount,
                    loan.get("startMonth", None),
                    loan.get("startYear", None),
                    loan.get("durationMonths", 0),
                    loan_amount  # 👈 this sets the initial balance = amount
                ))

        if loan_other and loan_other.get("name"):
                loan_other_amount = float(loan_other.get("amount", 0.0))
                cursor.execute("""
                    INSERT INTO employee_loans (
                        user_id, loan_type, loan_name, amount, 
                        start_month, start_year, duration_months, balance
                    )
                    VALUES (%s, 'other', %s, %s, %s, %s, %s, %s)
                """, (
                    user_id,
                    loan_other.get("name"),
                    loan_other_amount,
                    loan_other.get("startMonth", ""),
                    loan_other.get("startYear", ""),
                    loan_other.get("durationMonths", 0),
                    loan_other_amount  # 👈 again, set balance = amount
                ))
        connection.commit()
        return {"message": "Profile updated successfully"}

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()


# OCR Endpoint (Updated)
@app.post("/ocr")
async def ocr(
    file: UploadFile = File(...),
    username: str = Form(...),
    replace_existing: bool = Form(False),
):
    try:
        print(f"Processing DTR for user: {username}")
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Get user info
        cursor.execute("SELECT id, full_name FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid user")
        
        user_id = user["id"]
        full_name = user["full_name"].strip().upper()

        # Process file
        contents = await file.read()
        images = convert_from_bytes(contents, poppler_path=POPPLER_PATH) if file.filename.lower().endswith(".pdf") \
            else [Image.open(io.BytesIO(contents))]

        full_text = "\n\n".join([pytesseract.image_to_string(img) for img in images])
        dtr_sections = re.split(r'\n(?=DAILY TIME RECORD)', full_text, flags=re.IGNORECASE)

        def normalize(s):
            return s.strip().replace("\n", " ") if s else "Not found"

        def is_valid_name(candidate):
            return (
                candidate
                and not re.search(r'(DAILY TIME RECORD|FORM|CSC|OFFICIAL HOURS|REGULA|MONTH)', candidate.upper())
                and not re.match(r'^[A-Za-z]+\s+\d{1,2}[-–]\d{1,2},\s*\d{4}$', candidate)
                and len(candidate.split()) >= 2
                and not any(char.isdigit() for char in candidate)
            )

        extracted_data = []
        # Updated pattern to better handle day numbers (including '11' being misread as 'u')
        daily_pattern = re.compile(
            r'^([uU]|\d{1,2})\s+'  # Handles 'u' or 'U' which might be misread '11'
            r'(\d{1,2}:\d{2}\s*[APapmM]*)\s+'
            r'(\d{1,2}:\d{2}\s*[APapmM]*)\s+'
            r'(\d{1,2}:\d{2}\s*[APapmM]*)\s+'
            r'(\d{1,2}:\d{2}\s*[APapmM]*)\s*'
            r'(?:(\d+)\s*hrs?\s*(\d+)\s*mins?)?',
            re.MULTILINE | re.IGNORECASE
        )

        for dtr_text in dtr_sections:
            lines = [line.strip() for line in dtr_text.splitlines() if line.strip()]

            # Extract name
            name = "Not found"
            for i, line in enumerate(lines):
                if "NAME" in line.upper():
                    parts = re.split(r'NAME', line, flags=re.IGNORECASE)
                    if len(parts) > 1 and is_valid_name(parts[0].strip()):
                        name = parts[0].strip()
                        break
                    elif i > 0 and is_valid_name(lines[i - 1]):
                        name = lines[i - 1]
                        break
                    elif i + 1 < len(lines) and is_valid_name(lines[i + 1]):
                        name = lines[i + 1]
                        break

            if full_name not in name.upper():
                raise HTTPException(status_code=403, detail=f"DTR belongs to {name}, not the logged-in user.")

            # Extract month
            month_year_match = re.search(r'([A-Za-z]+),\s*(\d{4})', dtr_text)
            if not month_year_match:
                raise HTTPException(status_code=400, detail="Could not extract month and year from DTR")

            parsed_month = month_year_match.group(1).strip().capitalize()
            parsed_year = int(month_year_match.group(2).strip())

            # Check existing DTR and delete if replacing
            cursor.execute("""
                SELECT id FROM dtrs WHERE user_id = %s AND LOWER(month) = LOWER(%s) AND year = %s
            """, (user_id, parsed_month.lower(), parsed_year))
            existing_dtr = cursor.fetchone()

            if existing_dtr and not replace_existing:
                raise HTTPException(
                    status_code=409,
                    detail=f"You already uploaded a DTR for {parsed_month}. Set 'replace_existing' to true to replace it."
                )
            elif existing_dtr and replace_existing:
                # Delete existing daily records first
                cursor.execute("DELETE FROM dtr_days WHERE dtr_id = %s", (existing_dtr["id"],))
                # Then delete the DTR header
                cursor.execute("DELETE FROM dtrs WHERE id = %s", (existing_dtr["id"],))
                connection.commit()
                print(f"Deleted existing DTR {existing_dtr['id']} and its daily records for replacement")

            # Extract working hours
            working_hours = "Not found"
            working_match = re.search(
                r'Regular\s+days\s+'
                r'(\d{1,2}:\d{2})\s*([aApP][mM])?\s*[–\-]\s*'
                r'(\d{1,2}:\d{2})\s*([aApP][mM])?\s+and\s+'
                r'(\d{1,2}:\d{2})\s*([aApP][mM])?\s*[–\-]\s*'
                r'(\d{1,2}:\d{2})\s*([aApP][mM])?',
                dtr_text,
                re.IGNORECASE
            )
            if working_match:
                morning_start = f"{working_match.group(1)} {working_match.group(2) or ''}".strip()
                morning_end = f"{working_match.group(3)} {working_match.group(4) or ''}".strip()
                afternoon_start = f"{working_match.group(5)} {working_match.group(6) or ''}".strip()
                afternoon_end = f"{working_match.group(7)} {working_match.group(8) or ''}".strip()
                working_hours = f"{morning_start} - {morning_end} and {afternoon_start} - {afternoon_end}"

            # Extract other fields
            verified_match = re.search(r'\b(JUAN Z\. DELA CRUZ)\b', dtr_text, re.IGNORECASE)
            position_match = re.search(r'\b(Principal|Manager|Supervisor)\b', dtr_text, re.IGNORECASE)
            total_time_match = re.search(r'\bTOTAL\s+(\d+\s+hours\s+and\s+\d+\s+minutes)\b', dtr_text, re.IGNORECASE)

            parsed = {
                "name": normalize(name),
                "month": parsed_month,
                "year": parsed_year,
                "workingHours": normalize(working_hours),
                "verifiedBy": normalize(verified_match.group(1)) if verified_match else "Not found",
                "position": normalize(position_match.group(1)) if position_match else "Not found",
                "totalTime": normalize(total_time_match.group(1)) if total_time_match else "Not found",
                "dailyRecords": []
            }

            # Insert DTR header
            cursor.execute("""
                INSERT INTO dtrs (user_id, employee_name, month, year, working_hours, verified_by, position, total_time)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id, parsed["name"], parsed["month"], parsed["year"], parsed["workingHours"],
                parsed["verifiedBy"], parsed["position"], parsed["totalTime"]
            ))
            
            # Get inserted DTR ID
            cursor.execute("SELECT LAST_INSERT_ID() AS dtr_id")
            dtr_id = cursor.fetchone()["dtr_id"]
            print(f"Inserted DTR ID: {dtr_id}")

            # Process daily entries with improved validation
            daily_entries = []
            insert_values = []
            for match in daily_pattern.finditer(dtr_text):
                try:
                    day_str = match.group(1).upper()  # Convert to uppercase for 'U' check
                    
                    # Handle 'u' being misread as '11'
                    if day_str == 'U':
                        day = 11
                    else:
                        if not day_str.isdigit():
                            print(f"Skipping invalid day: {day_str}")
                            continue
                        day = int(day_str)
                    
                    if day < 1 or day > 31:
                        continue

                    # Normalize time format
                    def format_time(t):
                        t = re.sub(r'\s+', '', t).upper()
                        if not re.search(r'[AP]M$', t):
                            hour_part = t.split(':')[0]
                            if hour_part.isdigit():
                                hour = int(hour_part)
                                period = '' if hour < 12 else ''
                                return f"{t}{period}"
                        return t

                    am_arrival = format_time(match.group(2))
                    am_departure = format_time(match.group(3))
                    pm_arrival = format_time(match.group(4))
                    pm_departure = format_time(match.group(5))
                    
                    undertime_hours = int(match.group(6)) if match.group(6) else 0
                    undertime_minutes = int(match.group(7)) if match.group(7) else 0

                    daily_entries.append({
                        "day": day,
                        "am_arrival": am_arrival,
                        "am_departure": am_departure,
                        "pm_arrival": pm_arrival,
                        "pm_departure": pm_departure,
                        "undertime_hours": undertime_hours,
                        "undertime_minutes": undertime_minutes
                    })

                    insert_values.append((
                        dtr_id,
                        day,
                        am_arrival,
                        am_departure,
                        pm_arrival,
                        pm_departure,
                        undertime_hours,
                        undertime_minutes
                    ))

                except Exception as e:
                    print(f"Error processing day entry: {str(e)}")
                    continue

            # Batch insert daily entries
            if insert_values:
                cursor.executemany("""
                    INSERT INTO dtr_days 
                    (dtr_id, day, am_arrival, am_departure, pm_arrival, pm_departure, undertime_hours, undertime_minutes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, insert_values)
                print(f"Inserted {len(insert_values)} daily records for DTR {dtr_id}")

            connection.commit()
            parsed["dailyRecords"] = daily_entries
            extracted_data.append(parsed)

        return JSONResponse({
            "text": full_text,
            "parsedDTRs": extracted_data,
            "message": "DTR processed successfully",
            "database": {
                "dtrs_inserted": len(extracted_data),
                "days_inserted": sum(len(d["dailyRecords"]) for d in extracted_data)
            }
        })

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        if 'connection' in locals() and connection.is_connected():
            connection.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {err.msg}")
    except HTTPException:
        raise
    except Exception as err:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"OCR processing failed: {str(err)}")
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

#computation of salary
def clamp_time(actual_str, expected_str, direction="in"):
    actual = datetime.strptime(actual_str, "%H:%M").time()
    expected = datetime.strptime(expected_str, "%H:%M").time()
    return max(actual, expected) if direction == "in" else min(actual, expected)

def minutes_between(t1, t2):
    return (datetime.combine(datetime.today(), t2) - datetime.combine(datetime.today(), t1)).seconds / 60

def compute_daily_hours(entry):
    try:
        am_minutes, pm_minutes = 0, 0

        if entry["am_arrival"] and entry["am_departure"]:
            am_arrival = clamp_time(entry["am_arrival"], "08:00", "in")
            am_departure = clamp_time(entry["am_departure"], "12:00", "out")
            am_minutes = max(minutes_between(am_arrival, am_departure), 0)

        if entry["pm_arrival"] and entry["pm_departure"]:
            pm_arrival = clamp_time(entry["pm_arrival"], "13:00", "in")
            pm_departure = clamp_time(entry["pm_departure"], "17:00", "out")
            pm_minutes = max(minutes_between(pm_arrival, pm_departure), 0)

        undertime = (entry.get("undertime_hours", 0) * 60) + entry.get("undertime_minutes", 0)
        return max((am_minutes + pm_minutes - undertime) / 60, 0)
    except:
        return 0
    
@app.post("/compute_salary")
async def compute_salary(payload: SalaryRequest):
    try:
        print(f"⏩ Received payload: {payload.dict()}")
        
        username = payload.username
        month_str = payload.month_str.strip().capitalize()

        # Database connection
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # 1. Get user ID
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user_id = user["id"]
        
        # 2. Get DTR
        cursor.execute("""
            SELECT * FROM dtrs 
            WHERE user_id = %s 
            AND month = %s
            LIMIT 1
        """, (user_id, month_str))
        dtr = cursor.fetchone()
        if not dtr:
            raise HTTPException(status_code=404, detail=f"No DTR found for {month_str}")

        dtr_month = dtr["month"]
        dtr_year = dtr["year"]

        # 3. Calculate working days
        try:
            month_index = list(calendar.month_name).index(dtr_month)
            _, num_days = calendar.monthrange(dtr_year, month_index)
            working_days = sum(
                1 for day in range(1, num_days + 1)
                if datetime(dtr_year, month_index, day).weekday() < 5
            )
        except:
            working_days = 22  # Fallback value

        # 4. Get daily entries and compute hours + late minutes
        cursor.execute("SELECT * FROM dtr_days WHERE dtr_id = %s", (dtr["id"],))
        day_entries = cursor.fetchall()
        
        total_hours = 0.0
        total_late_minutes = 0
        days_present = 0
        
        for entry in day_entries:
            try:
                # Initialize variables for this day
                daily_hours = 0.0
                daily_late_minutes = 0
                
                # AM Arrival Late Calculation
                if entry["am_arrival"]:
                    try:
                        am_arrival = datetime.strptime(entry["am_arrival"], "%H:%M")
                        expected_am = datetime.strptime("08:00", "%H:%M")
                        if am_arrival > expected_am:
                            late_minutes = (am_arrival - expected_am).seconds // 60
                            daily_late_minutes += late_minutes
                    except Exception as e:
                        print(f"Error processing AM arrival: {str(e)}")
                
                # PM Arrival Late Calculation
                if entry["pm_arrival"]:
                    try:
                        pm_arrival = datetime.strptime(entry["pm_arrival"], "%H:%M")
                        expected_pm = datetime.strptime("13:00", "%H:%M")
                        if pm_arrival > expected_pm:
                            late_minutes = (pm_arrival - expected_pm).seconds // 60
                            daily_late_minutes += late_minutes
                    except Exception as e:
                        print(f"Error processing PM arrival: {str(e)}")
                
                # Calculate working hours
                try:
                    times = []
                    for period in ['am_arrival', 'am_departure', 'pm_arrival', 'pm_departure']:
                        if entry.get(period):
                            times.append(datetime.strptime(entry[period], "%H:%M"))
                    
                    if len(times) == 4:
                        am_hours = (times[1] - times[0]).seconds / 3600
                        pm_hours = (times[3] - times[2]).seconds / 3600
                        daily_hours = am_hours + pm_hours
                        days_present += 1
                except Exception as e:
                    print(f"Error calculating hours: {str(e)}")
                
                # Add to totals
                total_hours += daily_hours
                total_late_minutes += daily_late_minutes
                
            except Exception as e:
                print(f"Error processing day entry: {str(e)}")
                continue

        # 5. Get payroll profile
        cursor.execute("""
            SELECT base_salary_hour, employment_type, leave_credits,
                   gsis_deduction, philhealth_deduction, tax_deduction,
                   base_monthly_salary
            FROM employee_profiles WHERE user_id = %s
        """, (user_id,))
        profile = cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Payroll profile not found")

        # Convert all values to float with error handling
        try:
            rate = float(profile["base_salary_hour"])
            monthly_salary = float(profile["base_monthly_salary"])
            employment_type = profile["employment_type"]
            leave_credits = float(profile["leave_credits"] or 0)
            philhealth = float(profile["philhealth_deduction"] or 0)
            tax = float(profile["tax_deduction"] or 0)
            gsis = float(profile["gsis_deduction"] or 0)
        except (TypeError, ValueError) as e:
            raise HTTPException(status_code=500, detail=f"Invalid payroll values: {str(e)}")

        # Calculate late deduction (only for regular employees)
        late_deduction = 0.0
        if employment_type == "regular":
            # Convert late minutes to hours
            late_hours = total_late_minutes / 60
            # Calculate deduction based on hourly rate
            late_deduction = round(late_hours * rate, 2)
            print(f"⏱ Late deduction calculated: {late_deduction} (from {total_late_minutes} minutes)")

        # 6. Calculate gross income based on employment type
        if employment_type == "irregular":
            gross = total_hours * rate
            days_absent = 0
            leave_used = 0
        else:
            gross = monthly_salary
            days_absent = max(working_days - days_present, 0)
            leave_used = min(leave_credits, days_absent)
            unpaid_absent_days = max(days_absent - leave_used, 0)
            absent_deduction = round((monthly_salary / working_days) * unpaid_absent_days, 2)
            gross = monthly_salary - absent_deduction - late_deduction  # Deduct late penalty
            new_leave_credits = leave_credits - leave_used
            
            # Update leave credits in profile
            cursor.execute(
                "UPDATE employee_profiles SET leave_credits = %s WHERE user_id = %s",
                (new_leave_credits, user_id)
            )
            print(f"📝 Updated leave credits: {new_leave_credits}")

        # 7. Process Loans
        loan_deduction = 0.0
        loans_to_save = []
        try:
            cursor.execute("""
                SELECT id, loan_name, amount, duration_months, 
                    start_month, start_year, balance
                FROM employee_loans 
                WHERE user_id = %s AND balance > 0
            """, (user_id,))
            loans = cursor.fetchall()
            
            current_period = f"{dtr_month} {dtr_year}"
            
            for loan in loans:
                try:
                    # Handle month format
                    if loan['start_month'].isdigit():
                        month_num = int(loan['start_month'])
                        start_month = calendar.month_name[month_num]
                    else:
                        start_month = loan['start_month'].capitalize()
                    
                    loan_date = datetime.strptime(f"{start_month} {loan['start_year']}", "%B %Y")
                    current_date = datetime.strptime(current_period, "%B %Y")
                    
                    if current_date >= loan_date:
                        monthly_payment = round(float(loan['amount']) / loan['duration_months'], 2)
                        if monthly_payment > float(loan['balance']):
                            monthly_payment = float(loan['balance'])
                        
                        loan_deduction += monthly_payment
                        new_balance = round(float(loan['balance']) - monthly_payment, 2)
                        
                        loans_to_save.append({
                            'loan_name': loan['loan_name'],
                            'amount': monthly_payment
                        })
                        
                        cursor.execute(
                            "UPDATE employee_loans SET balance = %s WHERE id = %s",
                            (new_balance, loan['id'])
                        )
                        print(f"📝 Updated loan balance: {loan['loan_name']} = {new_balance}")
                except Exception as e:
                    print(f"Error processing loan {loan.get('id')}: {str(e)}")
                    continue
        except Exception as e:
            print(f"Loan processing failed: {str(e)}")

        # 8. Process Bonuses
        bonuses = 0.0
        bonuses_to_save = []
        try:
            cursor.execute("""
                SELECT amount, frequency, bonus_name 
                FROM employee_bonuses 
                WHERE user_id = %s
            """, (user_id,))
            
            bonuses_data = cursor.fetchall()
            for b in bonuses_data:
                try:
                    # Monthly bonuses always apply
                    if b["frequency"] == "monthly":
                        bonuses += float(b["amount"])
                        bonuses_to_save.append({
                            'bonus_name': b["bonus_name"],
                            'amount': float(b["amount"])
                        })
                    # Yearly bonuses only in December
                    elif b["frequency"] == "yearly" and dtr_month.lower() == "december":
                        bonuses += float(b["amount"])
                        bonuses_to_save.append({
                            'bonus_name': b["bonus_name"],
                            'amount': float(b["amount"])
                        })
                except Exception as e:
                    print(f"Error processing bonus: {str(e)}")
                    continue
        except Exception as e:
            print(f"Bonus processing failed: {str(e)}")

        # 9. Final calculations
        total_deductions = round(gsis + philhealth + tax + loan_deduction + late_deduction, 2)
        net = round(gross + bonuses - total_deductions, 2)

        # 10. Save payslip with late information
        cursor.execute("""
            INSERT INTO payslips (
                user_id, dtr_id, month, year,
                working_days, days_present, days_absent, leave_used,
                total_hours, late_minutes, late_deduction, gross_income, bonuses,
                philhealth_deduction, tax_deduction, loan_deduction,
                total_deductions, net_income, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            user_id, dtr["id"], dtr_month, dtr_year,
            working_days, days_present, days_absent, leave_used,
            round(total_hours, 2), total_late_minutes, late_deduction, round(gross, 2), round(bonuses, 2),
            philhealth, tax, round(loan_deduction, 2),
            total_deductions, net
        ))
        
        payslip_id = cursor.lastrowid
        print(f"💾 Saved payslip ID: {payslip_id}")

        # 11. Save loan deductions
        for loan in loans_to_save:
            cursor.execute("""
                INSERT INTO payslip_loan_deductions 
                (payslip_id, loan_name, amount)
                VALUES (%s, %s, %s)
            """, (payslip_id, loan['loan_name'], loan['amount']))

        # 12. Save bonuses
        for bonus in bonuses_to_save:
            cursor.execute("""
                INSERT INTO payslip_bonuses 
                (payslip_id, bonus_name, amount)
                VALUES (%s, %s, %s)
            """, (payslip_id, bonus['bonus_name'], bonus['amount']))

        # 13. Update DTR status
        cursor.execute("""
            UPDATE dtrs SET status = 'processed', processed_at = NOW()
            WHERE id = %s
        """, (dtr["id"],))

        connection.commit()

        return {
            "status": "success",
            "data": {
                "employee": dtr["employee_name"],
                "period": f"{dtr_month} {dtr_year}",
                "grossIncome": round(gross, 2),
                "lateMinutes": total_late_minutes, 
                "lateDeduction": late_deduction,
                "deductions": {
                    "philhealth": philhealth,
                    "tax": tax,
                    "loans": round(loan_deduction, 2),
                    "late": round(late_deduction, 2),
                    "total": total_deductions
                },
                "netPay": net
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        if 'connection' in locals() and connection.is_connected():
            connection.rollback()
        print(f"❌ Error: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

#fetching payslips
def format_month_for_db(month_str: str) -> tuple:
    """
    Convert input month format to database-compatible format
    Input formats accepted: "YYYY-MM" or "Month, Year"
    Returns: (month_name: str, year: int)
    """
    try:
        # Handle "YYYY-MM" format
        if '-' in month_str and len(month_str.split('-')) == 2:
            dt = datetime.strptime(month_str, "%Y-%m")
            return (dt.strftime("%B"), dt.year)
        
        # Handle "Month, Year" format
        elif ',' in month_str:
            parts = month_str.split(',')
            if len(parts) == 2:
                month_name = parts[0].strip()
                year = int(parts[1].strip())
                return (month_name, year)
        
        # Fallback for other formats
        return (month_str.strip(), 0)
    
    except ValueError as e:
        print(f"⚠️ Error parsing month string '{month_str}': {str(e)}")
        return (month_str.strip(), 0)

def parse_db_month_to_iso(month: str, year: int) -> str:
    """
    Convert database month and year back to ISO format "YYYY-MM"
    """
    try:
        dt = datetime.strptime(f"{month} {year}", "%B %Y")
        return dt.strftime("%Y-%m")
    except ValueError:
        return f"{year}-01"  # Fallback to January if parsing fails


@app.get("/payslip")
async def get_payslip(username: str, month: str, year: int):
    print(f"🔍 Fetching payslip for {username}, input month: {month}, input year: {year}")

    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # 🔎 Get user ID & full name
        cursor.execute("SELECT id, full_name FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_id = user["id"]
        full_name = user["full_name"]
        print(f"✅ Found user ID: {user_id}, Name: {full_name}")

        # 📅 Normalize month format
        parsed_month, parsed_year = format_month_for_db(month)
        normalized_month = parsed_month.strip().capitalize() if parsed_month else month.strip().capitalize()
        normalized_year = parsed_year if parsed_year != 0 else year
        print(f"📅 Normalized month: {normalized_month}, year: {normalized_year}")

        # 📄 Fetch payslip from DB
        cursor.execute("""
            SELECT *
            FROM payslips
            WHERE user_id = %s AND LOWER(TRIM(month)) = %s AND year = %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (user_id, normalized_month.lower(), normalized_year))

        payslip = cursor.fetchone()
        if not payslip:
            raise HTTPException(status_code=404, detail=f"No payslip found for {normalized_month} {normalized_year}")

        payslip_id = payslip["id"]
        print(f"📄 Found payslip ID: {payslip_id}")

        # 👔 Get employee profile
        cursor.execute("""
            SELECT employment_type, base_salary_hour, base_monthly_salary, salary_grade
            FROM employee_profiles
            WHERE user_id = %s
        """, (user_id,))
        profile = cursor.fetchone()

        employment_type = profile.get("employment_type", "irregular") if profile else "irregular"
        rate_per_hour = float(profile.get("base_salary_hour", 0)) if employment_type == "irregular" else None
        rate_per_month = float(profile.get("base_monthly_salary", 0)) if employment_type == "regular" else None

        # 🎁 Get bonuses
        cursor.execute("""
            SELECT bonus_name, amount
            FROM payslip_bonuses
            WHERE payslip_id = %s
        """, (payslip_id,))
        bonuses = [{"label": b["bonus_name"], "amount": float(b["amount"])} for b in cursor.fetchall()]

        # ⏱ Late Deduction (computed from late_minutes only for regular)
        late_minutes = int(payslip.get("late_minutes", 0))
        late_deduction = 0.0
        deductions = []  # ✅ fix the UnboundLocalError here

        # 🧾 Government deductions will be computed after late deduction
        # But for regular, compute hourly rate from monthly
        if employment_type.strip().lower() == "regular":
            monthly_salary = float(profile.get("base_monthly_salary", 0))
            working_days = int(payslip.get("working_days") or 22)
            hours_per_day = 8
            hourly_rate = round((monthly_salary / working_days) / hours_per_day, 2)
            print(f"🧮 Computed hourly_rate from monthly: {hourly_rate}")

            # ⏱ Late deduction logic
            late_minutes = int(payslip.get("late_minutes", 0))
            late_deduction = 0.0

            if employment_type.strip().lower() == "regular":
                monthly_salary = float(profile.get("base_monthly_salary", 0))
                working_days = int(payslip.get("working_days") or 22)
                hours_per_day = 8
                hourly_rate = round((monthly_salary / working_days) / hours_per_day, 2)
                late_deduction = round((late_minutes / 60) * hourly_rate, 2)
                print(f"💸 Computed late deduction: {late_deduction}")

                deductions.append({
                    "label": "Late Deduction",
                    "amount": late_deduction,
                    "balance": 0.0
                })

        # ✅ Adjust total deductions and net income for response
        existing_deductions = float(payslip.get("total_deductions", 0))
        existing_net = float(payslip.get("net_income", 0))

        total_deductions = existing_deductions + late_deduction
        net_income = existing_net - late_deduction
        cursor.execute("""
            INSERT INTO payslip_adjustments (payslip_id, late_deduction, total_deductions, net_income)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                late_deduction = VALUES(late_deduction),
                total_deductions = VALUES(total_deductions),
                net_income = VALUES(net_income),
                updated_at = NOW()
        """, (payslip_id, late_deduction, total_deductions, net_income))

        connection.commit()
        print("💾 Saved late deduction & adjustments to payslip_adjustments.")

        # 💸 Get loan deductions
        cursor.execute("""
            SELECT 
                pl.loan_name, 
                pl.amount,
                (SELECT balance FROM employee_loans 
                 WHERE user_id = %s AND loan_name = pl.loan_name
                 ORDER BY created_at DESC LIMIT 1) as balance
            FROM payslip_loan_deductions pl
            WHERE pl.payslip_id = %s
        """, (user_id, payslip_id))

        loan_deductions = []
        for l in cursor.fetchall():
            loan_deductions.append({
                "label": l["loan_name"],
                "amount": float(l["amount"]),
                "balance": float(l["balance"]) if l["balance"] is not None else 0.0
            })

        # 🧾 Government + Late Deductions
        gsis_amount = float(payslip.get("total_deductions", 0)) \
                      - float(payslip.get("loan_deduction", 0)) \
                      - float(payslip.get("tax_deduction", 0)) \
                      - float(payslip.get("philhealth_deduction", 0)) \
                      - late_deduction

        deductions = [
            {
                "label": "GSIS",
                "amount": gsis_amount,
                "balance": 0.0
            },
            {
                "label": "PhilHealth",
                "amount": float(payslip.get("philhealth_deduction", 0)),
                "balance": 0.0
            },
            {
                "label": "Tax",
                "amount": float(payslip.get("tax_deduction", 0)),
                "balance": 0.0
            }
        ]

        # Append late deduction only for regular employees
        if employment_type == "regular":
            deductions.append({
                "label": "Late Deduction",
                "amount": late_deduction,
                "balance": 0.0
            })

        # Add loan deductions
        deductions += loan_deductions

        # 📤 Final structured response
        response = {
            "fullName": full_name,
            "period": parse_db_month_to_iso(normalized_month, normalized_year),
            "employmentType": employment_type,
            "salaryGrade": profile.get("salary_grade") if profile else None,
            "ratePerHour": rate_per_hour,
            "ratePerMonth": rate_per_month,
            "totalHours": float(payslip.get("total_hours", 0)),
            "grossIncome": float(payslip.get("gross_income", 0)),
            "bonuses": bonuses,
            "deductions": deductions,
            "netPay": float(payslip.get("net_income", 0)),
            "status": "processed",
            "workingDays": payslip.get("working_days", 0),
            "daysPresent": payslip.get("days_present", 0),
            "daysAbsent": payslip.get("days_absent", 0),
            "leaveUsed": payslip.get("leave_used", 0),
            "lateMinutes": late_minutes,
            "lateDeduction": late_deduction,
            "netPay": round(net_income, 2),  # ✅ updated net pay
            "totalDeductions": round(total_deductions, 2)  # ✅ updated total
        }

        print(f"📤 Final response: {response}")
        return response

    except mysql.connector.Error as err:
        print(f"❌ MySQL error: {err}")
        raise HTTPException(status_code=500, detail=f"Database error: {err}")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching payslip: {str(e)}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


@app.get("/available-months")
async def get_available_months(username: str):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("""
            SELECT * FROM (
                SELECT DISTINCT TRIM(month) as month, year
                FROM payslips 
                WHERE user_id = %s
            ) AS months
            ORDER BY year DESC, STR_TO_DATE(CONCAT('01 ', month), '%%d %%M') DESC
        """, (user['id'],))
        
        results = cursor.fetchall()
        return [{"month": row["month"], "year": row["year"]} for row in results]

    except Exception as e:
        traceback.print_exc()  # <-- This will show the exact error in the console
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/payslip/latest")
async def get_latest_payslip(username: str):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Get user
        cursor.execute("SELECT id, full_name FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user_id = user["id"]

        # Get latest payslip
        cursor.execute("""
            SELECT * FROM payslips
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (user_id,))
        payslip = cursor.fetchone()
        if not payslip:
            raise HTTPException(status_code=404, detail="No payslip found")

        payslip_id = payslip["id"]

        # Fetch adjustments if available
        cursor.execute("SELECT total_deductions, net_income, late_deduction FROM payslip_adjustments WHERE payslip_id = %s", (payslip_id,))
        adjustment = cursor.fetchone()

        if adjustment:
            net_income = float(adjustment["net_income"])
            late_deduction = float(adjustment["late_deduction"])
        else:
            net_income = float(payslip["net_income"])
            late_deduction = 0.0

        # Bonuses
        cursor.execute("SELECT bonus_name, amount FROM payslip_bonuses WHERE payslip_id = %s", (payslip_id,))
        bonuses = [{"label": row["bonus_name"], "amount": float(row["amount"])} for row in cursor.fetchall()]

        # Loans
        cursor.execute("SELECT loan_name, amount FROM payslip_loan_deductions WHERE payslip_id = %s", (payslip_id,))
        loans = [{"label": row["loan_name"], "amount": float(row["amount"])} for row in cursor.fetchall()]

        # Add late deduction to the deduction list if applicable
        if late_deduction > 0:
            loans.append({
                "label": "Late Deduction",
                "amount": late_deduction
            })

        return {
            "fullName": user["full_name"],
            "period": f"{payslip['month']} {payslip['year']}",
            "grossIncome": float(payslip["gross_income"]),
            "netPay": net_income,  # ✅ Use adjusted if available
            "bonuses": bonuses,
            "deductions": loans
        }

    finally:
        if 'cursor' in locals(): cursor.close()
        if 'connection' in locals(): connection.close()

@app.post("/api/payslip/summary")
async def get_payslip_summary(data: MonthSelection):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Get user ID and employment info
        cursor.execute("""
            SELECT u.id, e.employment_type, e.base_salary_hour, e.base_monthly_salary, e.salary_grade, u.full_name
            FROM users u
            LEFT JOIN employee_profiles e ON u.id = e.user_id
            WHERE u.username = %s
        """, (data.username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_id = user["id"]
        full_name = user["full_name"]

        # Data containers
        monthly_summary = {}
        income_breakdown = defaultdict(lambda: defaultdict(float))
        deduction_breakdown = defaultdict(lambda: defaultdict(float))
        quarter_totals = defaultdict(float)
        month_list = []

        # Quarter label mapping
        quarter_map = {
            1: "Jan-Mar",
            2: "Apr-Jun",
            3: "Jul-Sep",
            4: "Oct-Dec"
        }

        for entry in data.selected_months:
            month = entry.month
            year = entry.year

            cursor.execute("""
                SELECT *
                FROM payslips
                WHERE user_id = %s AND month = %s AND year = %s
                ORDER BY created_at DESC
                LIMIT 1
            """, (user_id, month, year))
            payslip = cursor.fetchone()
            if not payslip:
                continue

            payslip_id = payslip["id"]
            month_key = f"{month} {year}"
            month_list.append(month_key)

            # Get quarter key for potential future use
            try:
                month_index = list(calendar.month_name).index(month.capitalize())
                quarter = (month_index - 1) // 3 + 1
                quarter_key = f"{quarter_map[quarter]} {year}"
            except:
                quarter_key = f"Q{month} {year}"

            gross = float(payslip.get("gross_income", 0))
            deductions = float(payslip.get("total_deductions", 0))
            net = float(payslip.get("net_income", 0))
            
            late_minutes = int(payslip.get("late_minutes", 0))
            late_deduction = 0.0
            if user.get("employment_type", "irregular").strip().lower() == "regular":
                monthly_salary = float(user.get("base_monthly_salary", 0))
                working_days = int(payslip.get("working_days") or 22)
                hourly_rate = round((monthly_salary / working_days) / 8, 2)
                late_deduction = round((late_minutes / 60) * hourly_rate, 2)

            deductions += late_deduction
            net -= late_deduction
            monthly_summary[month_key] = {
                "gross_income": gross,
                "total_deductions": deductions,
                "net_income": net,
                "quarter": quarter_key
            }
            quarter_totals[f"{quarter_key}_gross"] += gross
            quarter_totals[f"{quarter_key}_deductions"] += deductions
            quarter_totals[f"{quarter_key}_net"] += net

            if late_deduction > 0:
                deduction_breakdown["Late Deduction"][month_key] += late_deduction

            monthly_summary[month_key] = {
                "gross_income": gross,
                "total_deductions": deductions,
                "net_income": net,
                "quarter": quarter_key
            }

            quarter_totals[f"{quarter_key}_gross"] += gross
            quarter_totals[f"{quarter_key}_deductions"] += deductions
            quarter_totals[f"{quarter_key}_net"] += net

            # Base salary
            income_breakdown["Base Salary"][month_key] += gross

            # Bonuses
            cursor.execute("""
                SELECT bonus_name, amount
                FROM payslip_bonuses
                WHERE payslip_id = %s
            """, (payslip_id,))
            for bonus in cursor.fetchall():
                income_breakdown[bonus["bonus_name"]][month_key] += float(bonus["amount"])

            # Loan deductions
            cursor.execute("""
                SELECT pl.loan_name, pl.amount,
                       (SELECT balance FROM employee_loans 
                        WHERE user_id = %s AND loan_name = pl.loan_name
                        ORDER BY created_at DESC LIMIT 1) as balance
                FROM payslip_loan_deductions pl
                WHERE pl.payslip_id = %s
            """, (user_id, payslip_id))
            
            for loan in cursor.fetchall():
                deduction_breakdown[loan["loan_name"]][month_key] += float(loan["amount"])
                deduction_breakdown[f"{loan['loan_name']}_balance"][month_key] = float(loan["balance"]) if loan["balance"] is not None else 0.0

            # Gov deductions
            gsis = float(payslip.get("total_deductions", 0)) - float(payslip.get("loan_deduction", 0)) - float(payslip.get("tax_deduction", 0)) - float(payslip.get("philhealth_deduction", 0))
            philhealth = float(payslip.get("philhealth_deduction", 0))
            tax = float(payslip.get("tax_deduction", 0))

            deduction_breakdown["GSIS"][month_key] += gsis
            deduction_breakdown["PhilHealth"][month_key] += philhealth
            deduction_breakdown["Tax"][month_key] += tax

        # Compute totals
        total_gross = sum(month["gross_income"] for month in monthly_summary.values())
        total_deductions = sum(month["total_deductions"] for month in monthly_summary.values())
        total_net = sum(month["net_income"] for month in monthly_summary.values())

        quarter_summary = {}
        for quarter in set(m["quarter"] for m in monthly_summary.values()):
            quarter_summary[quarter] = {
                "gross_income": quarter_totals[f"{quarter}_gross"],
                "total_deductions": quarter_totals[f"{quarter}_deductions"],
                "net_income": quarter_totals[f"{quarter}_net"]
            }

        return {
            "fullName": full_name,
            "employmentType": user.get("employment_type", "regular"),
            "salaryGrade": user.get("salary_grade", ""),
            "monthlySummary": monthly_summary,
            "quarterSummary": quarter_summary,  # still useful for charts
            "incomeBreakdown": dict(income_breakdown),
            "deductionBreakdown": dict(deduction_breakdown),
            "totals": {
                "gross_income": total_gross,
                "total_deductions": total_deductions,
                "net_income": total_net
            },
            "months": month_list
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/api/records")
async def get_user_records(username: str = Query(...)):
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Get user ID
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_id = user["id"]

        # Get payslip records
        cursor.execute("""
            SELECT 
                p.id AS payslip_id,
                p.month, 
                p.year,
                p.gross_income,
                p.total_deductions AS original_deductions,
                p.net_income AS original_net,
                p.created_at
            FROM payslips p
            WHERE p.user_id = %s
            ORDER BY p.year DESC, 
                     STR_TO_DATE(CONCAT('01 ', p.month), '%%d %%M') DESC
        """, (user_id,))
        
        payslips = cursor.fetchall()  # ✅ Fully consume the result set
        formatted = []

        for row in payslips:
            payslip_id = row["payslip_id"]

            # ✅ Use a new cursor or ensure result is consumed before next query
            adj_cursor = connection.cursor(dictionary=True)
            adj_cursor.execute(
                "SELECT total_deductions, net_income FROM payslip_adjustments WHERE payslip_id = %s",
                (payslip_id,)
            )
            adjustment = adj_cursor.fetchone()
            adj_cursor.close()  # ✅ Always close extra cursors

            total_deductions = float(adjustment["total_deductions"]) if adjustment else float(row["original_deductions"])
            net_income = float(adjustment["net_income"]) if adjustment else float(row["original_net"])
            gross_income = float(row["gross_income"])

            # Format period
            try:
                date_obj = datetime.strptime(f"{row['month']} {row['year']}", "%B %Y")
                formatted.append({
                    "period": date_obj.strftime("%Y-%m"),
                    "displayMonth": date_obj.strftime("%B %Y"),
                    "gross_income": gross_income,
                    "total_deductions": total_deductions,
                    "net_income": net_income,
                    "created_at": row["created_at"].strftime("%Y-%m-%d")
                })
            except Exception as e:
                print(f"⚠️ Skip malformed record: {str(e)}")
                continue

        return formatted

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if connection.is_connected():
            connection.close()
