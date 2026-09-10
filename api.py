from flask import Blueprint, jsonify, session

from database import get_user, get_user_transactions

api = Blueprint("api", __name__, url_prefix="/api")


def api_login_required():
    return "username" in session


@api.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "SecurePayX API",
        "status": "operational",
        "security": "enabled"
    })


@api.route("/profile", methods=["GET"])
def profile():

    if not api_login_required():
        return jsonify({
            "error": "Authentication required"
        }), 401

    user = get_user(session["username"])

    return jsonify({
        "username": user["username"],
        "role": user["role"],
        "balance": user["balance"]
    })


@api.route("/transactions", methods=["GET"])
def transactions():

    if not api_login_required():
        return jsonify({
            "error": "Authentication required"
        }), 401

    transactions = get_user_transactions(
        session["username"]
    )

    return jsonify([
        {
            "transaction_id": transaction["transaction_id"],
            "sender": transaction["sender"],
            "recipient": transaction["recipient"],
            "amount": transaction["amount"],
            "risk_score": transaction["risk_score"],
            "status": transaction["status"],
            "created_at": transaction["created_at"]
        }
        for transaction in transactions
    ])