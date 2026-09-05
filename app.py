from flask import Flask, request, jsonify
from flask_cors import CORS
from database import get_connection

import bcrypt
import jwt
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ============================================================
# FLASK CONFIGURATION
# ============================================================

app = Flask(__name__)
CORS(app)

JWT_SECRET = os.getenv(
    "JWT_SECRET",
    "SecureJointBank_2026_ChangeThisSecret"
)

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 2


# ============================================================
# BASIC ROUTES
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Secure Joint Bank Backend",
        "status": "OK"
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "OK"
    })


# ============================================================
# DATABASE HELPER
# ============================================================

def execute_query(query, params=None, fetchone=False, fetchall=False,
                  commit=False):
    connection = None

    try:
        connection = get_connection()

        with connection.cursor() as cursor:
            cursor.execute(query, params or ())

            if commit:
                connection.commit()

            if fetchone:
                return cursor.fetchone()

            if fetchall:
                return cursor.fetchall()

            return None

    finally:
        if connection:
            connection.close()


# ============================================================
# SECURITY EVENT LOGGER
# ============================================================

def log_security_event(
    transaction_id,
    event_type,
    actor=None,
    original_value=None,
    modified_value=None,
    detected=0
):
    try:
        execute_query(
            """
            INSERT INTO security_events
            (
                transaction_id,
                event_type,
                actor,
                original_value,
                modified_value,
                detected
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                transaction_id,
                event_type,
                actor,
                original_value,
                modified_value,
                detected
            ),
            commit=True
        )
    except Exception as e:
        print("Security event logging error:", e)


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password):
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(password, password_hash):
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8")
        )
    except Exception:
        return False


# ============================================================
# JWT FUNCTIONS
# ============================================================

def create_token(user_id):
    now = datetime.now(timezone.utc)

    payload = {
        "user_id": user_id,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS)
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def get_authenticated_user():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None, ("Authorization header required", 401)

    if not auth_header.startswith("Bearer "):
        return None, ("Invalid Authorization header", 401)

    token = auth_header.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

        user_id = payload.get("user_id")

        if not user_id:
            return None, ("Invalid token", 401)

        user = execute_query(
            """
            SELECT
                user_id,
                name,
                mobile,
                email,
                public_key,
                biometric_enabled,
                status
            FROM users
            WHERE user_id = %s
            """,
            (user_id,),
            fetchone=True
        )

        if not user:
            return None, ("User not found", 401)

        if user["status"] != "ACTIVE":
            return None, ("User account is not active", 403)

        return user, None

    except jwt.ExpiredSignatureError:
        return None, ("Token expired", 401)

    except jwt.InvalidTokenError:
        return None, ("Invalid token", 401)


# ============================================================
# USER ROUTES
# ============================================================

@app.route("/users", methods=["GET"])
def get_users():
    try:
        users = execute_query(
            """
            SELECT
                user_id,
                name,
                mobile,
                email,
                biometric_enabled,
                status
            FROM users
            ORDER BY user_id
            """,
            fetchall=True
        )

        return jsonify(users)

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    name = data.get("name")
    mobile = data.get("mobile")
    email = data.get("email")
    password = data.get("password")
    public_key = data.get("public_key")

    if not name or not mobile or not password:
        return jsonify({
            "error": "Name, mobile and password are required"
        }), 400

    existing = execute_query(
        """
        SELECT user_id
        FROM users
        WHERE mobile = %s
        """,
        (mobile,),
        fetchone=True
    )

    if existing:
        return jsonify({
            "error": "Mobile number already registered"
        }), 409

    if email:
        existing_email = execute_query(
            """
            SELECT user_id
            FROM users
            WHERE email = %s
            """,
            (email,),
            fetchone=True
        )

        if existing_email:
            return jsonify({
                "error": "Email already registered"
            }), 409

    password_hash = hash_password(password)

    execute_query(
        """
        INSERT INTO users
        (
            name,
            mobile,
            email,
            password_hash,
            public_key,
            biometric_enabled,
            status
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            name,
            mobile,
            email,
            password_hash,
            public_key,
            0,
            "ACTIVE"
        ),
        commit=True
    )

    user = execute_query(
        """
        SELECT user_id, name, mobile, email
        FROM users
        WHERE mobile = %s
        """,
        (mobile,),
        fetchone=True
    )

    return jsonify({
        "message": "User registered successfully",
        "user": user
    }), 201


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}

    mobile = data.get("mobile")
    password = data.get("password")

    if not mobile or not password:
        return jsonify({
            "error": "Mobile number and password are required"
        }), 400

    user = execute_query(
        """
        SELECT
            user_id,
            name,
            mobile,
            email,
            password_hash,
            public_key,
            biometric_enabled,
            status
        FROM users
        WHERE mobile = %s
        """,
        (mobile,),
        fetchone=True
    )

    if not user:
        return jsonify({
            "error": "Invalid mobile number or password"
        }), 401

    if user["status"] != "ACTIVE":
        return jsonify({
            "error": "User account is not active"
        }), 403

    if not verify_password(password, user["password_hash"]):
        return jsonify({
            "error": "Invalid mobile number or password"
        }), 401

    token = create_token(user["user_id"])

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "user_id": user["user_id"],
            "name": user["name"],
            "mobile": user["mobile"],
            "email": user["email"],
            "biometric_enabled": user["biometric_enabled"],
            "status": user["status"]
        }
    })


# ============================================================
# TRANSACTION HASH
# ============================================================

def create_transaction_hash(
    account_id,
    initiated_by,
    beneficiary,
    amount,
    required_approvals
):
    transaction_data = {
        "account_id": int(account_id),
        "initiated_by": int(initiated_by),
        "beneficiary": str(beneficiary),
        "amount": str(amount),
        "required_approvals": int(required_approvals)
    }

    canonical_data = json.dumps(
        transaction_data,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()


# ============================================================
# TRANSACTION DATA HASH FROM DATABASE
# ============================================================

def calculate_transaction_hash_from_row(transaction):
    return create_transaction_hash(
        transaction["account_id"],
        transaction["initiated_by"],
        transaction["beneficiary"],
        transaction["amount"],
        transaction["required_approvals"]
    )


# ============================================================
# GET TRANSACTION
# ============================================================

def get_transaction(transaction_id):
    return execute_query(
        """
        SELECT
            transaction_id,
            account_id,
            initiated_by,
            beneficiary,
            amount,
            transaction_hash,
            required_approvals,
            status,
            created_at,
            expires_at
        FROM transactions
        WHERE transaction_id = %s
        """,
        (transaction_id,),
        fetchone=True
    )


# ============================================================
# CREATE TRANSACTION
# ============================================================

@app.route("/transactions", methods=["POST"])
def create_transaction():
    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    data = request.get_json() or {}

    account_id = data.get("account_id")
    beneficiary = data.get("beneficiary")
    amount = data.get("amount")

    if account_id is None or not beneficiary or amount is None:
        return jsonify({
            "error": "account_id, beneficiary and amount are required"
        }), 400

    try:
        amount = float(amount)

        if amount <= 0:
            return jsonify({
                "error": "Amount must be greater than zero"
            }), 400

    except (ValueError, TypeError):
        return jsonify({
            "error": "Invalid amount"
        }), 400

    account = execute_query(
        """
        SELECT
            account_id,
            account_number,
            total_members,
            required_approvals,
            balance,
            status
        FROM joint_accounts
        WHERE account_id = %s
        """,
        (account_id,),
        fetchone=True
    )

    if not account:
        return jsonify({
            "error": "Joint account not found"
        }), 404

    if account["status"] != "ACTIVE":
        return jsonify({
            "error": "Joint account is not active"
        }), 403

    membership = execute_query(
        """
        SELECT account_id, user_id, role
        FROM account_members
        WHERE account_id = %s
        AND user_id = %s
        """,
        (account_id, user["user_id"]),
        fetchone=True
    )

    if not membership:
        return jsonify({
            "error": "User is not a member of this joint account"
        }), 403

    if amount > float(account["balance"]):
        return jsonify({
            "error": "Insufficient balance"
        }), 400

    required_approvals = int(account["required_approvals"])

    transaction_hash = create_transaction_hash(
        account_id,
        user["user_id"],
        beneficiary,
        amount,
        required_approvals
    )

    connection = get_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO transactions
                (
                    account_id,
                    initiated_by,
                    beneficiary,
                    amount,
                    transaction_hash,
                    required_approvals,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    account_id,
                    user["user_id"],
                    beneficiary,
                    amount,
                    transaction_hash,
                    required_approvals,
                    "PENDING"
                )
            )

            transaction_id = cursor.lastrowid

            connection.commit()

    finally:
        connection.close()

    log_security_event(
        transaction_id,
        "TRANSACTION_CREATED",
        str(user["user_id"])
    )

    return jsonify({
        "message": "Transaction created successfully",
        "transaction_id": transaction_id,
        "transaction_hash": transaction_hash,
        "required_approvals": required_approvals,
        "status": "PENDING"
    }), 201


# ============================================================
# GET TRANSACTIONS FOR USER
# ============================================================

@app.route("/transactions", methods=["GET"])
def list_transactions():
    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    transactions = execute_query(
        """
        SELECT DISTINCT
            t.transaction_id,
            t.account_id,
            t.initiated_by,
            t.beneficiary,
            t.amount,
            t.transaction_hash,
            t.required_approvals,
            t.status,
            t.created_at,
            t.expires_at
        FROM transactions t
        INNER JOIN account_members am
            ON t.account_id = am.account_id
        WHERE am.user_id = %s
        ORDER BY t.created_at DESC
        """,
        (user["user_id"],),
        fetchall=True
    )

    return jsonify(transactions)


# ============================================================
# GET SINGLE TRANSACTION
# ============================================================

@app.route("/transactions/<int:transaction_id>", methods=["GET"])
def get_single_transaction(transaction_id):
    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    transaction = get_transaction(transaction_id)

    if not transaction:
        return jsonify({
            "error": "Transaction not found"
        }), 404

    membership = execute_query(
        """
        SELECT account_id
        FROM account_members
        WHERE account_id = %s
        AND user_id = %s
        """,
        (
            transaction["account_id"],
            user["user_id"]
        ),
        fetchone=True
    )

    if not membership:
        return jsonify({
            "error": "You are not a member of this joint account"
        }), 403

    return jsonify(transaction)


# ============================================================
# APPROVE TRANSACTION
# ============================================================

@app.route(
    "/transactions/<int:transaction_id>/approve",
    methods=["POST"]
)
def approve_transaction(transaction_id):

    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    transaction = get_transaction(transaction_id)

    if not transaction:
        return jsonify({
            "error": "Transaction not found"
        }), 404

    if transaction["status"] != "PENDING":
        return jsonify({
            "error": "Transaction is not pending"
        }), 400

    user_id = user["user_id"]

    # --------------------------------------------------------
    # Initiator cannot approve own transaction
    # --------------------------------------------------------

    if int(transaction["initiated_by"]) == int(user_id):
        return jsonify({
            "error": "Transaction initiator cannot approve the transaction"
        }), 403

    # --------------------------------------------------------
    # Check membership
    # --------------------------------------------------------

    membership = execute_query(
        """
        SELECT account_id, user_id, role
        FROM account_members
        WHERE account_id = %s
        AND user_id = %s
        """,
        (
            transaction["account_id"],
            user_id
        ),
        fetchone=True
    )

    if not membership:
        return jsonify({
            "error": "User is not a member of this joint account"
        }), 403

    # --------------------------------------------------------
    # Prevent duplicate approval
    # --------------------------------------------------------

    existing_approval = execute_query(
        """
        SELECT
            approval_id,
            decision
        FROM approvals
        WHERE transaction_id = %s
        AND user_id = %s
        """,
        (
            transaction_id,
            user_id
        ),
        fetchone=True
    )

    if existing_approval:
        return jsonify({
            "error": "User has already approved this transaction"
        }), 409

    # --------------------------------------------------------
    # Recalculate transaction hash
    # --------------------------------------------------------

    calculated_hash = calculate_transaction_hash_from_row(
        transaction
    )

    stored_hash = transaction["transaction_hash"]

    if calculated_hash != stored_hash:

        log_security_event(
            transaction_id,
            "TAMPERING_DETECTED",
            "SYSTEM",
            str(stored_hash),
            str(calculated_hash),
            1
        )

        return jsonify({
            "error": "Transaction integrity verification failed",
            "hash_valid": False,
            "cryptographically_authorized": False
        }), 409

    # --------------------------------------------------------
    # Load server-side private key
    # --------------------------------------------------------

    private_key_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "private_keys",
        f"user_{user_id}_private.pem"
    )

    if not os.path.exists(private_key_path):
        return jsonify({
            "error": "Private key not found for this user"
        }), 500

    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

    except Exception as e:
        return jsonify({
            "error": "Unable to load private key",
            "details": str(e)
        }), 500

    # --------------------------------------------------------
    # Create RSA digital signature
    # --------------------------------------------------------

    try:
        signature = private_key.sign(
            calculated_hash.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    except Exception as e:
        return jsonify({
            "error": "Signature generation failed",
            "details": str(e)
        }), 500

    signature_text = signature.hex()

    # --------------------------------------------------------
    # Verify signature before storing
    # --------------------------------------------------------

    public_key_text = user["public_key"]

    if not public_key_text:
        return jsonify({
            "error": "User public key not registered"
        }), 500

    try:
        public_key = serialization.load_pem_public_key(
            public_key_text.encode("utf-8")
        )

        public_key.verify(
            signature,
            calculated_hash.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    except Exception:
        return jsonify({
            "error": "Digital signature verification failed"
        }), 500

    # --------------------------------------------------------
    # Store approval
    # --------------------------------------------------------

    connection = get_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO approvals
                (
                    transaction_id,
                    user_id,
                    authentication_status,
                    biometric_verified,
                    decision,
                    cryptographic_proof,
                    signature,
                    approval_time
                )
                VALUES
                (%s, %s, %s, %s, %s, %s, %s, NOW())
                """,
                (
                    transaction_id,
                    user_id,
                    1,
                    0,
                    "APPROVED",
                    calculated_hash,
                    signature_text
                )
            )

            connection.commit()

    finally:
        connection.close()

    # --------------------------------------------------------
    # Count valid cryptographic approvals
    # --------------------------------------------------------

    approvals = execute_query(
        """
        SELECT
            approval_id,
            user_id,
            cryptographic_proof,
            signature,
            decision
        FROM approvals
        WHERE transaction_id = %s
        AND decision = 'APPROVED'
        """,
        (transaction_id,),
        fetchall=True
    )

    valid_count = 0

    for approval in approvals:

        if approval["cryptographic_proof"] != calculated_hash:
            continue

        try:
            approval_user = execute_query(
                """
                SELECT public_key
                FROM users
                WHERE user_id = %s
                """,
                (approval["user_id"],),
                fetchone=True
            )

            if not approval_user or not approval_user["public_key"]:
                continue

            approval_public_key = serialization.load_pem_public_key(
                approval_user["public_key"].encode("utf-8")
            )

            approval_public_key.verify(
                bytes.fromhex(approval["signature"]),
                calculated_hash.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            valid_count += 1

        except Exception:
            continue

    # --------------------------------------------------------
    # Threshold decision
    # --------------------------------------------------------

    required = int(transaction["required_approvals"])

    new_status = "PENDING"

    if valid_count >= required:

        connection = get_connection()

        try:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    UPDATE transactions
                    SET status = 'APPROVED'
                    WHERE transaction_id = %s
                    """,
                    (transaction_id,)
                )

                connection.commit()

        finally:
            connection.close()

        new_status = "APPROVED"

        log_security_event(
            transaction_id,
            "TRANSACTION_THRESHOLD_REACHED",
            "SYSTEM",
            str(required),
            str(valid_count),
            0
        )

    return jsonify({
        "message": "Transaction approved successfully",
        "transaction_id": transaction_id,
        "approved_by": user_id,
        "approval_count": valid_count,
        "required_approvals": required,
        "status": new_status,
        "cryptographic_proof": calculated_hash,
        "signature": signature_text
    })


# ============================================================
# VERIFY TRANSACTION
# ============================================================

@app.route("/verify/<int:transaction_id>", methods=["GET"])
def verify_transaction(transaction_id):

    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    transaction = get_transaction(transaction_id)

    if not transaction:
        return jsonify({
            "error": "Transaction not found"
        }), 404

    membership = execute_query(
        """
        SELECT account_id
        FROM account_members
        WHERE account_id = %s
        AND user_id = %s
        """,
        (
            transaction["account_id"],
            user["user_id"]
        ),
        fetchone=True
    )

    if not membership:
        return jsonify({
            "error": "Access denied"
        }), 403

    stored_hash = transaction["transaction_hash"]

    calculated_hash = calculate_transaction_hash_from_row(
        transaction
    )

    hash_valid = stored_hash == calculated_hash

    if not hash_valid:

        log_security_event(
            transaction_id,
            "TAMPERING_DETECTED",
            "SYSTEM",
            str(stored_hash),
            str(calculated_hash),
            1
        )

    approvals = execute_query(
        """
        SELECT
            approval_id,
            user_id,
            authentication_status,
            biometric_verified,
            decision,
            cryptographic_proof,
            signature,
            approval_time
        FROM approvals
        WHERE transaction_id = %s
        AND decision = 'APPROVED'
        ORDER BY approval_time
        """,
        (transaction_id,),
        fetchall=True
    )

    valid_signatures = 0
    approval_details = []

    for approval in approvals:

        signature_valid = False

        if (
            hash_valid
            and approval["cryptographic_proof"] == stored_hash
            and approval["signature"]
        ):

            approval_user = execute_query(
                """
                SELECT
                    user_id,
                    name,
                    public_key
                FROM users
                WHERE user_id = %s
                """,
                (approval["user_id"],),
                fetchone=True
            )

            if approval_user and approval_user["public_key"]:

                try:
                    public_key = serialization.load_pem_public_key(
                        approval_user["public_key"].encode("utf-8")
                    )

                    public_key.verify(
                        bytes.fromhex(approval["signature"]),
                        stored_hash.encode("utf-8"),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )

                    signature_valid = True
                    valid_signatures += 1

                except Exception:
                    signature_valid = False

            approval_details.append({
                "approval_id": approval["approval_id"],
                "user_id": approval["user_id"],
                "user_name": (
                    approval_user["name"]
                    if approval_user
                    else None
                ),
                "decision": approval["decision"],
                "signature_valid": signature_valid,
                "approval_time": approval["approval_time"]
            })

    required = int(transaction["required_approvals"])

    threshold_valid = (
        valid_signatures >= required
    )

    cryptographically_authorized = (
        hash_valid
        and threshold_valid
    )

    return jsonify({
        "transaction_id": transaction_id,
        "database_status": transaction["status"],
        "stored_hash": stored_hash,
        "calculated_hash": calculated_hash,
        "hash_valid": hash_valid,
        "valid_signatures": valid_signatures,
        "required_approvals": required,
        "threshold_valid": threshold_valid,
        "cryptographically_authorized": cryptographically_authorized,
        "approvals": approval_details
    })


# ============================================================
# GET APPROVALS
# ============================================================

@app.route(
    "/transactions/<int:transaction_id>/approvals",
    methods=["GET"]
)
def get_approvals(transaction_id):

    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    transaction = get_transaction(transaction_id)

    if not transaction:
        return jsonify({
            "error": "Transaction not found"
        }), 404

    membership = execute_query(
        """
        SELECT account_id
        FROM account_members
        WHERE account_id = %s
        AND user_id = %s
        """,
        (
            transaction["account_id"],
            user["user_id"]
        ),
        fetchone=True
    )

    if not membership:
        return jsonify({
            "error": "Access denied"
        }), 403

    approvals = execute_query(
        """
        SELECT
            a.approval_id,
            a.transaction_id,
            a.user_id,
            u.name,
            a.authentication_status,
            a.biometric_verified,
            a.decision,
            a.cryptographic_proof,
            a.signature,
            a.approval_time
        FROM approvals a
        INNER JOIN users u
            ON a.user_id = u.user_id
        WHERE a.transaction_id = %s
        ORDER BY a.approval_time
        """,
        (transaction_id,),
        fetchall=True
    )

    return jsonify(approvals)


# ============================================================
# SECURITY EVENTS
# ============================================================

@app.route(
    "/security-events/<int:transaction_id>",
    methods=["GET"]
)
def security_events(transaction_id):

    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    transaction = get_transaction(transaction_id)

    if not transaction:
        return jsonify({
            "error": "Transaction not found"
        }), 404

    membership = execute_query(
        """
        SELECT account_id
        FROM account_members
        WHERE account_id = %s
        AND user_id = %s
        """,
        (
            transaction["account_id"],
            user["user_id"]
        ),
        fetchone=True
    )

    if not membership:
        return jsonify({
            "error": "Access denied"
        }), 403

    events = execute_query(
        """
        SELECT
            event_id,
            transaction_id,
            event_type,
            actor,
            original_value,
            modified_value,
            detected,
            event_time
        FROM security_events
        WHERE transaction_id = %s
        ORDER BY event_time ASC
        """,
        (transaction_id,),
        fetchall=True
    )

    return jsonify(events)


# ============================================================
# EXECUTE TRANSACTION
# ============================================================

@app.route(
    "/transactions/<int:transaction_id>/execute",
    methods=["POST"]
)
def execute_transaction(transaction_id):

    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    transaction = get_transaction(transaction_id)

    if not transaction:
        return jsonify({
            "error": "Transaction not found"
        }), 404

    # --------------------------------------------------------
    # Membership
    # --------------------------------------------------------

    membership = execute_query(
        """
        SELECT account_id
        FROM account_members
        WHERE account_id = %s
        AND user_id = %s
        """,
        (
            transaction["account_id"],
            user["user_id"]
        ),
        fetchone=True
    )

    if not membership:
        return jsonify({
            "error": "Access denied"
        }), 403

    # --------------------------------------------------------
    # Already executed
    # --------------------------------------------------------

    if transaction["status"] == "EXECUTED":
        return jsonify({
            "error": "Transaction has already been executed"
        }), 400

    # --------------------------------------------------------
    # Verify transaction integrity
    # --------------------------------------------------------

    stored_hash = transaction["transaction_hash"]

    calculated_hash = calculate_transaction_hash_from_row(
        transaction
    )

    if stored_hash != calculated_hash:

        log_security_event(
            transaction_id,
            "TAMPERING_DETECTED",
            "SYSTEM",
            str(stored_hash),
            str(calculated_hash),
            1
        )

        return jsonify({
            "error": "Transaction integrity verification failed",
            "hash_valid": False,
            "cryptographically_authorized": False
        }), 409

    # --------------------------------------------------------
    # Verify cryptographic approvals
    # --------------------------------------------------------

    approvals = execute_query(
        """
        SELECT
            approval_id,
            user_id,
            cryptographic_proof,
            signature,
            decision
        FROM approvals
        WHERE transaction_id = %s
        AND decision = 'APPROVED'
        """,
        (transaction_id,),
        fetchall=True
    )

    valid_signatures = 0
    valid_approvers = []

    for approval in approvals:

        if approval["cryptographic_proof"] != stored_hash:
            continue

        if not approval["signature"]:
            continue

        approval_user = execute_query(
            """
            SELECT
                user_id,
                name,
                public_key
            FROM users
            WHERE user_id = %s
            """,
            (approval["user_id"],),
            fetchone=True
        )

        if not approval_user:
            continue

        if not approval_user["public_key"]:
            continue

        try:

            public_key = serialization.load_pem_public_key(
                approval_user["public_key"].encode("utf-8")
            )

            public_key.verify(
                bytes.fromhex(approval["signature"]),
                stored_hash.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            valid_signatures += 1

            valid_approvers.append(
                approval["user_id"]
            )

        except Exception:
            continue

    required = int(transaction["required_approvals"])

    if valid_signatures < required:

        return jsonify({
            "error": "Required approval threshold not reached",
            "valid_signatures": valid_signatures,
            "required_approvals": required,
            "cryptographically_authorized": False
        }), 403

    # --------------------------------------------------------
    # Database status must also be APPROVED
    # --------------------------------------------------------

    if transaction["status"] != "APPROVED":

        return jsonify({
            "error": "Transaction is not marked APPROVED",
            "valid_signatures": valid_signatures,
            "required_approvals": required,
            "cryptographically_authorized": True,
            "database_status": transaction["status"]
        }), 403

    # --------------------------------------------------------
    # Lock account and execute transfer
    # --------------------------------------------------------

    connection = get_connection()

    try:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    account_id,
                    account_number,
                    balance,
                    status
                FROM joint_accounts
                WHERE account_id = %s
                FOR UPDATE
                """,
                (transaction["account_id"],)
            )

            account = cursor.fetchone()

            if not account:

                connection.rollback()

                return jsonify({
                    "error": "Joint account not found"
                }), 404

            if account["status"] != "ACTIVE":

                connection.rollback()

                return jsonify({
                    "error": "Joint account is not active"
                }), 403

            current_balance = float(account["balance"])
            transaction_amount = float(transaction["amount"])

            if current_balance < transaction_amount:

                connection.rollback()

                return jsonify({
                    "error": "Insufficient account balance"
                }), 400

            new_balance = (
                current_balance - transaction_amount
            )

            cursor.execute(
                """
                UPDATE joint_accounts
                SET balance = %s
                WHERE account_id = %s
                """,
                (
                    new_balance,
                    transaction["account_id"]
                )
            )

            cursor.execute(
                """
                UPDATE transactions
                SET status = 'EXECUTED'
                WHERE transaction_id = %s
                """,
                (transaction_id,)
            )

            connection.commit()

    except Exception as e:

        connection.rollback()

        return jsonify({
            "error": "Transaction execution failed",
            "details": str(e)
        }), 500

    finally:
        connection.close()

    # --------------------------------------------------------
    # Audit log
    # --------------------------------------------------------

    log_security_event(
        transaction_id,
        "TRANSFER_EXECUTED",
        str(user["user_id"]),
        str(current_balance),
        str(new_balance),
        0
    )

    return jsonify({
        "message": "Transaction executed successfully",
        "transaction_id": transaction_id,
        "amount": transaction_amount,
        "old_balance": current_balance,
        "new_balance": new_balance,
        "status": "EXECUTED",
        "valid_signatures": valid_signatures,
        "required_approvals": required,
        "valid_approvers": valid_approvers,
        "cryptographically_authorized": True
    })


# ============================================================
# GET JOINT ACCOUNTS FOR LOGGED-IN USER
# ============================================================

@app.route("/accounts", methods=["GET"])
def get_accounts():

    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    accounts = execute_query(
        """
        SELECT
            ja.account_id,
            ja.account_number,
            ja.account_type,
            ja.total_members,
            ja.required_approvals,
            ja.balance,
            ja.status,
            am.role
        FROM joint_accounts ja
        INNER JOIN account_members am
            ON ja.account_id = am.account_id
        WHERE am.user_id = %s
        ORDER BY ja.account_id
        """,
        (user["user_id"],),
        fetchall=True
    )

    return jsonify(accounts)


# ============================================================
# GET ACCOUNT MEMBERS
# ============================================================

@app.route(
    "/accounts/<int:account_id>/members",
    methods=["GET"]
)
def get_account_members(account_id):

    user, error = get_authenticated_user()

    if error:
        return jsonify({
            "error": error[0]
        }), error[1]

    membership = execute_query(
        """
        SELECT account_id
        FROM account_members
        WHERE account_id = %s
        AND user_id = %s
        """,
        (
            account_id,
            user["user_id"]
        ),
        fetchone=True
    )

    if not membership:
        return jsonify({
            "error": "Access denied"
        }), 403

    members = execute_query(
        """
        SELECT
            am.account_id,
            am.user_id,
            am.role,
            u.name,
            u.mobile,
            u.email,
            u.biometric_enabled,
            u.status
        FROM account_members am
        INNER JOIN users u
            ON am.user_id = u.user_id
        WHERE am.account_id = %s
        ORDER BY am.user_id
        """,
        (account_id,),
        fetchall=True
    )

    return jsonify(members)


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "error": "Method not allowed"
    }), 405


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error"
    }), 500


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )