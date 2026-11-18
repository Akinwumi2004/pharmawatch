from risk_engine.indicators import derive_indicators
from risk_engine.scoring import calculate_risk
from risk_engine.scoring import INDICATOR_WEIGHTS
import csv
import io
from functools import wraps
from flask import session, flash
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash


from flask import Flask, render_template, redirect, url_for, request , make_response
from datetime import datetime
import mysql.connector
from mysql.connector import Error

from config import Config

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY


def get_db_connection():
    return mysql.connector.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME,
        connection_timeout=5,
    )

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))

            if session.get("role") not in allowed_roles:
                return "You are not authorised to perform this action.", 403

            return view(*args, **kwargs)

        return wrapped_view

    return decorator


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute("""
                SELECT id, username, password_hash,
                       full_name, role, is_active
                FROM users
                WHERE username = %s
            """, (username,))

            user = cursor.fetchone()

            if (
                user
                and user["is_active"]
                and check_password_hash(user["password_hash"], password)
            ):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["full_name"] = user["full_name"]
                session["role"] = user["role"]

                return redirect(url_for("dashboard"))

            flash("Invalid username or password.", "danger")

        except Exception:
            app.logger.exception("Login failed")
            flash("Unable to process login. Please try again.", "danger")

        finally:
            if cursor is not None:
                cursor.close()

            if connection is not None and connection.is_connected():
                connection.close()

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have successfully logged out.", "success")
    return redirect(url_for("login"))



@app.route("/manage-users", methods=["GET", "POST"])
@roles_required("admin")
def manage_users():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            full_name = request.form.get("full_name", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "").strip()

            allowed_roles = (
                "admin",
                "surveillance_officer",
                "regulatory_viewer"
            )

            if not username or not full_name or not password:
                flash("All fields are required.", "danger")

            elif len(username) > 50 or len(full_name) > 100:
                flash("Username or full name is too long.", "danger")

            elif len(password) < 12:
                flash("Password must contain at least 12 characters.", "danger")

            elif role not in allowed_roles:
                flash("Select a valid user role.", "danger")

            else:
                cursor.execute(
                    "SELECT id FROM users WHERE username = %s",
                    (username,)
                )

                if cursor.fetchone():
                    flash("That username already exists.", "danger")
                else:
                    password_hash = generate_password_hash(password)

                    cursor.execute("""
                        INSERT INTO users
                            (username, password_hash, full_name, role)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        username,
                        password_hash,
                        full_name,
                        role
                    ))

                    connection.commit()
                    flash("User account created successfully.", "success")

        cursor.execute("""
            SELECT id, username, full_name, role,
                   is_active, created_at
            FROM users
            ORDER BY created_at DESC
        """)

        users = cursor.fetchall()

        return render_template("manage_users.html", users=users)

    except Exception:
        if connection is not None:
            connection.rollback()

        app.logger.exception("User management failed")
        return "Could not process user management.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


@app.route("/manage-users/toggle/<int:user_id>", methods=["POST"])
@roles_required("admin")
def toggle_user(user_id):
    if user_id == session.get("user_id"):
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("manage_users"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, is_active FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        if user is None:
            return "User not found.", 404

        new_status = 0 if user["is_active"] else 1

        cursor.execute("""
            UPDATE users
            SET is_active = %s
            WHERE id = %s
        """, (new_status, user_id))

        connection.commit()

        flash(
            "User account updated successfully.",
            "success"
        )

        return redirect(url_for("manage_users"))

    except Exception:
        if connection is not None:
            connection.rollback()

        app.logger.exception("User status update failed")
        return "Could not update user account.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()



@app.route("/")
@login_required
def home():
    return render_template("batches.html")


@app.route("/assessment")
@login_required
def assessment_page():
    return redirect(url_for("batches"))


@app.route("/batches")
@login_required
def batches():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                batch_code,
                product_name,
                product_id,
                expiry_date,
                batch_status
            FROM drug_batches
            ORDER BY id ASC
        """)

        records = cursor.fetchall()

        return render_template(
            "batches.html",
            batches=records,
            error=None,
        )

    except Error:
        app.logger.exception("Database query failed")
        return render_template(
            "batches.html",
            batches=[],
            error=(
                "Could not retrieve batch records. "
                "Check that XAMPP MySQL is running and "
                "your database settings are correct."
            ),
        ), 500

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()



@app.route("/assess/<int:batch_id>", methods=["POST"])
@roles_required("admin", "surveillance_officer")
def assess_batch(batch_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM drug_batches WHERE id = %s",
            (batch_id,),
        )
        batch = cursor.fetchone()

        if batch is None:
            return "Batch not found", 404

        cursor.execute(
            """
            SELECT verification_result, verified_at,
                   verification_location, device_reference
            FROM verification_records
            WHERE batch_id = %s
            ORDER BY verified_at
            """,
            (batch_id,),
        )
        records = cursor.fetchall()

        indicators = derive_indicators(batch, records)
        result = calculate_risk(indicators)

        # Safety escalation is separate from the weighted score.
        status = (batch["batch_status"] or "").lower()
        if status in ("expired", "recalled"):
            result["surveillance_priority"] = "urgent_review"

        cursor.execute(
            """
            INSERT INTO risk_assessments
                (batch_id, risk_score, risk_level,
                 surveillance_priority, model_version)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                batch_id,
                result["risk_score"],
                result["risk_level"],
                result["surveillance_priority"],
                "prototype-1.0",
            ),
        )
        assessment_id = cursor.lastrowid

        for name, value in indicators.items():
            weight = INDICATOR_WEIGHTS[name]
            contribution = result["contributions"][name]

            cursor.execute(
                """
                INSERT INTO risk_indicator_results
                    (assessment_id, indicator_code, indicator_value,
                     weight, weighted_contribution, explanation)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    assessment_id,
                    name,
                    value,
                    weight,
                    contribution,
                    f"{name.replace('_', ' ').capitalize()}: "
                    f"indicator value {value}",
                ),
            )

        connection.commit()

        return render_template(
            "assessment.html",
            batch=batch,
            result=result,
            indicators=indicators,
        )

    except Exception:
        if connection is not None:
            connection.rollback()
        app.logger.exception("Risk assessment failed")
        return "Assessment failed. Check the VS Code terminal log.", 500

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


@app.route("/dashboard")
@login_required
def dashboard():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                b.id,
                b.batch_code,
                b.product_name,
                b.batch_status,
                COALESCE(ra.risk_score, 0) AS risk_score,
                COALESCE(ra.risk_level, 'not assessed') AS risk_level,
                COALESCE(
                    ra.surveillance_priority,
                    'pending assessment'
                ) AS surveillance_priority
            FROM drug_batches b
            LEFT JOIN (
                SELECT r1.*
                FROM risk_assessments r1
                INNER JOIN (
                    SELECT batch_id, MAX(id) AS latest_id
                    FROM risk_assessments
                    GROUP BY batch_id
                ) latest ON latest.latest_id = r1.id
            ) ra ON ra.batch_id = b.id
            ORDER BY ra.risk_score DESC
        """)

        batches = cursor.fetchall()
        return render_template("dashboard.html", batches=batches)

    except Exception:
        app.logger.exception("Dashboard loading failed")
        return "Dashboard failed. Check the VS Code terminal.", 500

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()




@app.route("/export-report")
@login_required
def export_report():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                b.batch_code,
                b.product_name,
                b.expiry_date,
                b.batch_status,
                ra.risk_score,
                ra.risk_level,
                ra.surveillance_priority,
                ra.assessed_at
            FROM drug_batches b
            LEFT JOIN (
                SELECT r1.*
                FROM risk_assessments r1
                INNER JOIN (
                    SELECT batch_id, MAX(id) AS latest_id
                    FROM risk_assessments
                    GROUP BY batch_id
                ) latest ON latest.latest_id = r1.id
            ) ra ON ra.batch_id = b.id
            ORDER BY ra.risk_score DESC
        """)

        records = cursor.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Batch Code",
            "Product Name",
            "Expiry Date",
            "Batch Status",
            "Risk Score",
            "Risk Level",
            "Surveillance Priority",
            "Assessment Date"
        ])

        for record in records:
            writer.writerow([
                record["batch_code"],
                record["product_name"],
                record["expiry_date"],
                record["batch_status"],
                record["risk_score"]
                if record["risk_score"] is not None else "",
                record["risk_level"] or "Not assessed",
                record["surveillance_priority"] or "Pending assessment",
                record["assessed_at"]
                if record["assessed_at"] is not None else ""
            ])

        response = make_response(output.getvalue())

        response.headers["Content-Disposition"] = (
            "attachment; filename=counterfeit_drug_surveillance_report.csv"
        )
        response.headers["Content-Type"] = "text/csv; charset=utf-8"

        return response

    except Exception:
        app.logger.exception("Report export failed")
        return "Could not generate report. Check the VS Code terminal.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()



@app.route("/batch/<int:batch_id>/verifications", methods=["GET", "POST"])
@login_required
def verification_records(batch_id):
    connection = None
    cursor = None
    error = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Confirm that the batch exists.
        cursor.execute(
            "SELECT * FROM drug_batches WHERE id = %s",
            (batch_id,)
        )
        batch = cursor.fetchone()

        if batch is None:
            return "Batch not found", 404

        if request.method == "POST":
            if session.get("role") not in ("admin", "surveillance_officer"):
                return "You are not authorised to add verification records.", 403
            verification_result = request.form.get(
                "verification_result", ""
            ).strip().lower()

            verified_at_input = request.form.get(
                "verified_at", ""
            ).strip()

            location = request.form.get(
                "verification_location", ""
            ).strip()

            device = request.form.get(
                "device_reference", ""
            ).strip()

            # Validate required fields.
            if verification_result not in ("success", "failure"):
                error = "Select a valid verification result."

            elif not verified_at_input:
                error = "Verification date and time are required."

            else:
                try:
                    verified_at = datetime.strptime(
                        verified_at_input,
                        "%Y-%m-%dT%H:%M"
                    )

                    cursor.execute(
                        """
                        INSERT INTO verification_records
                        (batch_id, verification_result, verified_at,
                         verification_location, device_reference)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (
                            batch_id,
                            verification_result,
                            verified_at,
                            location or None,
                            device or None
                        )
                    )

                    connection.commit()

                    return redirect(
                        url_for(
                            "verification_records",
                            batch_id=batch_id
                        )
                    )

                except ValueError:
                    error = "Invalid date and time."

        # Retrieve all verification records for this batch.
        cursor.execute(
            """
            SELECT *
            FROM verification_records
            WHERE batch_id = %s
            ORDER BY verified_at DESC
            """,
            (batch_id,)
        )

        records = cursor.fetchall()

        return render_template(
            "verification_records.html",
            batch=batch,
            records=records,
            error=error
        )

    except Exception:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Verification record operation failed")
        return "Could not process verification records.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()



@app.route("/upload-verifications", methods=["GET", "POST"])
@roles_required("admin", "surveillance_officer")
def upload_verifications():
    if request.method == "POST":

        uploaded_file = request.files.get("csv_file")

        if not uploaded_file or uploaded_file.filename == "":
            flash("Please select a CSV file.", "danger")
            return redirect(url_for("upload_verifications"))

        if not uploaded_file.filename.lower().endswith(".csv"):
            flash("Only CSV files are allowed.", "danger")
            return redirect(url_for("upload_verifications"))

        connection = None
        cursor = None

        try:
            file_content = uploaded_file.read().decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(file_content))

            required_columns = {
                "batch_code",
                "verification_result",
                "verified_at",
                "verification_location",
                "device_reference"
            }

            if not reader.fieldnames:
                flash("The CSV file is empty or has no headings.", "danger")
                return redirect(url_for("upload_verifications"))

            actual_columns = {
                column.strip() for column in reader.fieldnames
                if column
            }

            if not required_columns.issubset(actual_columns):
                flash(
                    "CSV headings are incorrect. Please use the provided template.",
                    "danger"
                )
                return redirect(url_for("upload_verifications"))

            rows = list(reader)

            if not rows:
                flash("The CSV file contains no verification records.", "danger")
                return redirect(url_for("upload_verifications"))

            if len(rows) > 5000:
                flash("A maximum of 5,000 records can be uploaded at once.", "danger")
                return redirect(url_for("upload_verifications"))

            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            valid_records = []

            for row_number, row in enumerate(rows, start=2):

                # Remove accidental spaces from headings and values.
                row = {
                    str(key).strip(): (value or "").strip()
                    for key, value in row.items()
                    if key is not None
                }

                batch_code = row.get("batch_code", "")
                result = row.get("verification_result", "").lower()
                verified_at_text = row.get("verified_at", "")
                location = row.get("verification_location", "")
                device_reference = row.get("device_reference", "")

                if not all([
                    batch_code,
                    result,
                    verified_at_text,
                    location,
                    device_reference
                ]):
                    raise ValueError(
                        f"Row {row_number}: All five fields are required."
                    )

                if result not in ("success", "failure"):
                    raise ValueError(
                        f"Row {row_number}: Result must be success or failure."
                    )

                try:
                    verified_at = datetime.fromisoformat(
                        verified_at_text.replace("Z", "+00:00")
                    )

                    if verified_at.tzinfo is not None:
                        raise ValueError(
                            "Use a local date and time without a timezone."
                        )

                except ValueError:
                    raise ValueError(
                        f"Row {row_number}: Invalid date/time. "
                        "Use YYYY-MM-DD HH:MM:SS."
                    )

                cursor.execute(
                    """
                    SELECT id
                    FROM drug_batches
                    WHERE batch_code = %s
                    """,
                    (batch_code,)
                )

                batch = cursor.fetchone()

                if batch is None:
                    raise ValueError(
                        f"Row {row_number}: Batch code '{batch_code}' "
                        "does not exist."
                    )

                valid_records.append((
                    batch["id"],
                    result,
                    verified_at,
                    location,
                    device_reference
                ))

            cursor.executemany(
                """
                INSERT INTO verification_records
                (
                    batch_id,
                    verification_result,
                    verified_at,
                    verification_location,
                    device_reference
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                valid_records
            )

            connection.commit()

            flash(
                f"Successfully uploaded {len(valid_records)} verification records.",
                "success"
            )

            return redirect(url_for("upload_verifications"))

        except UnicodeDecodeError:
            if connection is not None:
                connection.rollback()

            flash("The file must be saved using UTF-8 encoding.", "danger")

        except ValueError as error:
            if connection is not None:
                connection.rollback()

            flash(str(error), "danger")

        except Exception:
            if connection is not None:
                connection.rollback()

            app.logger.exception("CSV verification upload failed")
            flash("An error occurred while uploading the CSV file.", "danger")

        finally:
            if cursor is not None:
                cursor.close()

            if connection is not None and connection.is_connected():
                connection.close()

    return render_template("upload_verifications.html")



if __name__ == "__main__":
    app.run(debug=True)
