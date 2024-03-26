import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    id = session["user_id"]
    rows = db.execute("SELECT symbol, SUM(shares) AS shares FROM portfolio WHERE user_id = ? GROUP BY symbol", id)
    total_value = 0
    for row in rows:
        quoted = lookup(row["symbol"])
        row["name"] = quoted["name"]
        row["price"] = quoted["price"]
        row["value"] = row["shares"] * row["price"]
        total_value = total_value + row["value"]
    cash = db.execute("SELECT cash FROM users WHERE id=?", id)[0]["cash"]
    grand_total = total_value + cash
    return render_template("index.html", rows=rows, cash=cash, grand_total=grand_total)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change Password"""
    id = session["user_id"]
    if request.method == "POST":
        if not request.form.get("current_password"):
            return apology("missing current_password", 400)
        elif not request.form.get("new_password"):
            return apology("missing new password", 400)
        elif not request.form.get("confirmation") or (request.form.get("new_password") != request.form.get("confirmation")):
            return apology("passwords don't match", 400)
        elif (request.form.get("current_password") == request.form.get("new_password")):
            return apology("current and new password can't be same", 400)
        rows = db.execute("SELECT hash FROM users WHERE id = ?", id)
        if (check_password_hash(rows[0]["hash"], request.form.get("current_password")) == True):
            password = request.form.get("new_password")
            hash = generate_password_hash(password,method='pbkdf2:sha256', salt_length=8)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, id)
        else:
            return apology("incorrect password", 400)
        return redirect("/")
    else:
        return render_template("password.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("missing symbol", 400)
        elif (lookup(symbol) == None):
            return apology("invalid symbol", 400)
        try:
            shares = int(shares)
            if shares < 1:
                return apology("Value must be greater than or equal to 1", 400)
        except ValueError:
            return apology("Value must be greater than or equal to 1", 400)
        db.execute("CREATE TABLE IF NOT EXISTS portfolio (user_id INTEGER NOT NULL, symbol TEXT NOT NULL, name TEXT NOT NULL, shares NUMERIC NOT NULL, price REAL NOT NULL, value REAL AS (shares * price) NOT NULL, transacted TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id))")
        quoted = lookup(request.form.get("symbol"))
        name = quoted["name"]
        price = quoted["price"]
        value = shares * price
        id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id=?", id)[0]["cash"]
        if (cash) < value:
            return apology("can't afford", 400)
        else:
            db.execute("INSERT INTO portfolio (user_id, symbol, name, shares, price, transacted) VALUES(?, ?, ?, ?, ?, ?)",
                       id, symbol, name, shares, price, db.execute("SELECT DATETIME('now')")[0]["DATETIME('now')"])
            cash = (cash - value)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, id)
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    id = session["user_id"]
    rows = db.execute("SELECT * FROM portfolio WHERE user_id = ? ORDER BY transacted DESC", id)
    for row in rows:
        if row["shares"] > 0:
            row["order"] = "Buy"
        elif row["shares"] < 0:
            row["order"] = "Sell"
    for row in rows:
        if row["value"] < 0:
            row["value"] = (-1 * row["value"])
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)
        elif (lookup(request.form.get("symbol")) == None):
            return apology("invalid symbol", 400)

        quoted = lookup(request.form.get("symbol"))
        name = quoted["name"]
        symbol = quoted["symbol"]
        price = usd(quoted["price"])
        return render_template("quoted.html", name=name, symbol=symbol, price=price)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("missing username", 400)
        elif not request.form.get("password"):
            return apology("missing password", 400)
        elif not request.form.get("confirmation") or (request.form.get("password") != request.form.get("confirmation")):
            return apology("passwords don't match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 0:
            return apology("username is not available", 400)

        username = request.form.get("username")
        password = request.form.get("password")
        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    id = session["user_id"]

    stocks = db.execute("SELECT symbol, SUM(shares) AS shares FROM portfolio WHERE user_id = ? GROUP BY symbol", id)
    if request.method == "POST":
        quoted = lookup(request.form.get("symbol"))
        symbol = request.form.get("symbol")
        name = quoted["name"]
        shares = request.form.get("shares")
        price = quoted["price"]
        stocks_list = []
        for stock in stocks:
            stocks_list.append(stock["symbol"])
        if symbol not in stocks_list:
            return apology("Stock not owned", 400)
        elif int(shares) > stock["shares"]:
            return apology("too many shares", 400)
        try:
            shares = int(shares)
            if shares < 1:
                return apology("Value must be greater than or equal to 1", 400)
        except ValueError:
            return apology("Value must be greater than or equal to 1", 400)
        db.execute("INSERT INTO portfolio (user_id, symbol, name, shares, price, transacted) VALUES(?, ?, ?, ?, ?, ?)",
                   id, symbol, name, (-1 * shares), price, db.execute("SELECT DATETIME('now')")[0]["DATETIME('now')"])
        cash = db.execute("SELECT cash FROM users WHERE id=?", id)[0]["cash"]
        value = shares * price
        cash = (cash + value)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, id)
        return redirect("/")
    else:
        return render_template("sell.html", stocks=stocks)
