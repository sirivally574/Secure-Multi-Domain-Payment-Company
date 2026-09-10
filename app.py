import os
import secrets
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)

from database import (
    initialize_database,
    create_user,
    get_user,
    get_all_users,
    update_balance,
    add_transaction,
    get_user_transactions,
    get_all_transactions,
    add_security_event,
    get_security_events,
    get_statistics
)

from security import (
    validate_username,
    validate_password,
    verify_password,
    validate_amount
)

from payment_engine import evaluate_transaction


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "securepayx-development-secret"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

initialize_database()


# -------------------------
# Security Helpers
# -------------------------

def get_client_ip():
    return request.remote_addr or "Unknown"


def log_event(username, event_type, description):
    add_security_event(
        username,
        event_type,
        description,
        get_client_ip()
    )


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            flash("Please login to continue.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            flash("Please login to continue.", "error")
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            log_event(
                session.get("username", "Unknown"),
                "UNAUTHORIZED_ACCESS",
                "Attempted to access administrator portal"
            )

            return render_template(
                "error.html",
                code=403,
                message="You are not authorized to access this area."
            ), 403

        return view(*args, **kwargs)

    return wrapped_view


# -------------------------
# Main Website
# -------------------------

@app.route("/")
def home():
    return render_template("home.html")


# -------------------------
# Registration
# -------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        valid_username, username_error = validate_username(username)

        if not valid_username:
            flash(username_error, "error")
            return render_template("register.html")

        valid_password, password_error = validate_password(password)

        if not valid_password:
            flash(password_error, "error")
            return render_template("register.html")

        if not create_user(username, password):

            log_event(
                username,
                "REGISTRATION_FAILED",
                "Registration failed because username already exists"
            )

            flash(
                "Username already exists.",
                "error"
            )

            return render_template("register.html")

        log_event(
            username,
            "ACCOUNT_CREATED",
            "New customer account registered"
        )

        flash(
            "Account created successfully. Please login.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# -------------------------
# Login
# -------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if "username" in session:
        return redirect(url_for("customer_portal"))

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        user = get_user(username)

        if user and verify_password(
            password,
            user["password_hash"]
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            log_event(
                username,
                "LOGIN_SUCCESS",
                "Successful authentication"
            )

            if user["role"] == "admin":
                return redirect(url_for("admin_portal"))

            return redirect(url_for("customer_portal"))

        log_event(
            username or "Unknown",
            "LOGIN_FAILED",
            "Invalid login credentials"
        )

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template("login.html")


# -------------------------
# Logout
# -------------------------

@app.route("/logout")
def logout():

    username = session.get(
        "username",
        "Unknown"
    )

    if "username" in session:

        log_event(
            username,
            "LOGOUT",
            "User logged out"
        )

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))


# -------------------------
# Customer Portal
# -------------------------

@app.route("/customer")
@login_required
def customer_portal():

    user = get_user(
        session["username"]
    )

    transactions = get_user_transactions(
        session["username"]
    )

    return render_template(
        "customer.html",
        user=user,
        transactions=transactions
    )


# -------------------------
# Payment Application
# -------------------------

@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():

    if request.method == "POST":

        recipient = request.form.get(
            "recipient",
            ""
        ).strip()

        amount_input = request.form.get(
            "amount",
            ""
        ).strip()

        valid_amount, amount_result = validate_amount(
            amount_input
        )

        if not valid_amount:

            log_event(
                session["username"],
                "PAYMENT_BLOCKED",
                "Invalid payment amount"
            )

            flash(
                amount_result,
                "error"
            )

            return render_template(
                "payment.html"
            )

        amount = amount_result

        sender = get_user(
            session["username"]
        )

        risk = evaluate_transaction(
            amount,
            sender["balance"],
            recipient
        )

        transaction_id = (
            "SPX-"
            + secrets.token_hex(4).upper()
        )

        status = risk["decision"]

        if status == "APPROVED":

            update_balance(
                session["username"],
                sender["balance"] - amount
            )

            recipient_user = get_user(
                recipient
            )

            if recipient_user:

                update_balance(
                    recipient,
                    recipient_user["balance"] + amount
                )

            add_transaction(
                transaction_id,
                session["username"],
                recipient,
                amount,
                risk["risk_score"],
                status
            )

            log_event(
                session["username"],
                "PAYMENT_APPROVED",
                f"Demo payment of ₹{amount:.2f} approved"
            )

            return render_template(
                "payment_result.html",
                transaction_id=transaction_id,
                amount=amount,
                recipient=recipient,
                risk=risk,
                status=status
            )

        else:

            add_transaction(
                transaction_id,
                session["username"],
                recipient,
                amount,
                risk["risk_score"],
                status
            )

            log_event(
                session["username"],
                "PAYMENT_BLOCKED",
                "Payment failed security validation"
            )

            return render_template(
                "payment_result.html",
                transaction_id=transaction_id,
                amount=amount,
                recipient=recipient,
                risk=risk,
                status=status
            )

    return render_template(
        "payment.html"
    )


# -------------------------
# Transaction History
# -------------------------

@app.route("/transactions")
@login_required
def transactions():

    transaction_list = get_user_transactions(
        session["username"]
    )

    return render_template(
        "transactions.html",
        transactions=transaction_list
    )


# -------------------------
# Security Center
# -------------------------

@app.route("/security")
@login_required
def security_center():

    return render_template(
        "security_center.html"
    )


# -------------------------
# Admin Portal
# -------------------------

@app.route("/admin")
@admin_required
def admin_portal():

    statistics = get_statistics()

    users = get_all_users()

    transactions = get_all_transactions()

    events = get_security_events()

    return render_template(
        "admin.html",
        statistics=statistics,
        users=users,
        transactions=transactions,
        events=events
    )


# -------------------------
# Security Information
# -------------------------

@app.route("/security-info")
def security_info():

    return render_template(
        "security_info.html"
    )


# -------------------------
# API - Health Check
# -------------------------

@app.route("/api/health")
def api_health():

    return jsonify({
        "service": "SecurePayX API",
        "status": "operational",
        "security": "enabled"
    })


# -------------------------
# API - Current User
# -------------------------

@app.route("/api/profile")
@login_required
def api_profile():

    user = get_user(
        session["username"]
    )

    return jsonify({
        "username": user["username"],
        "role": user["role"],
        "balance": user["balance"]
    })


# -------------------------
# API - Transactions
# -------------------------

@app.route("/api/transactions")
@login_required
def api_transactions():

    transactions = get_user_transactions(
        session["username"]
    )

    return jsonify([
        {
            "transaction_id": item["transaction_id"],
            "sender": item["sender"],
            "recipient": item["recipient"],
            "amount": item["amount"],
            "risk_score": item["risk_score"],
            "status": item["status"],
            "created_at": item["created_at"]
        }
        for item in transactions
    ])


# -------------------------
# Error Handling
# -------------------------

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "error.html",
        code=404,
        message="The requested page could not be found."
    ), 404


@app.errorhandler(500)
def server_error(error):

    return render_template(
        "error.html",
        code=500,
        message="An internal server error occurred."
    ), 500


# -------------------------
# Run Application
# -------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )