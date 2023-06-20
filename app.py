import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks and handle stock quote"""

    portfolio = db.execute("SELECT symbol, stock_price, SUM(quantity) as qty, SUM(total_buy) AS total_buy FROM purchase_history WHERE user_id = ? GROUP BY symbol HAVING qty > 0", session["user_id"])
    users = db.execute("SELECT cash, username FROM users WHERE id = ?", session["user_id"])
    totalStockValue = db.execute("SELECT SUM(total_buy) AS total FROM purchase_history WHERE user_id = ?", session["user_id"])[0]["total"]
    cashBalance = users[0]["cash"]
    totalEquity = cashBalance + (totalStockValue if totalStockValue else 0)

    if request.method == "POST":
        ticker = request.form.get("symbol")
        if not ticker:
            return apology("Please enter a symbol", 400)
        symbol = lookup(ticker)

        if not symbol:
            return apology("Stock does not exist", 400)

        return render_template("index.html", symbol=symbol, portfolio=portfolio, users=users, total=totalEquity)

    message = session.pop("message", None)
    return render_template("index.html", portfolio=portfolio, users=users, total=totalEquity, message=message)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = lookup(request.form.get("symbol"))
        shares = request.form.get("shares")

        if not symbol:
            return apology("Stock does not exist", 400)
        if not shares:
            return apology("Please enter an amount", 400)

        shares = int(shares)
        if shares < 0:
            return apology("Please enter a positive amount", 400)

        sharePrice = symbol["price"]
        totalPurchaseOrder = float(shares) * sharePrice

        # return error if no funds left to buy
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        if cash - totalPurchaseOrder < 0:
            return apology("You have insufficient funds", 400)

        currentDateTime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Update DB with new cash balance after purchase
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", totalPurchaseOrder, session["user_id"])
        # Add purcchase to database into new table
        db.execute("INSERT INTO purchase_history(user_id, symbol, stock_price, quantity, total_buy, purchase_date) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], symbol["name"], sharePrice, shares, totalPurchaseOrder, currentDateTime)

        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * from purchase_history WHERE user_id = ?", session["user_id"])

    return render_template("history.html", transactions=transactions)


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



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Please enter a username", 400)
        elif not request.form.get("password"):
            return apology("Please enter a password", 400)

        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) > 0:
            return apology("Username exists. Please login", 400)

        if password == confirm:
            db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, generate_password_hash(password))
            return redirect("/")
        else:
            return apology("Password does not match", 400)

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    symbols = db.execute("SELECT * FROM purchase_history WHERE user_id = ? GROUP BY symbol HAVING SUM(quantity) > 0", session["user_id"])

    """Sell shares of stock"""
    if request.method == "POST":
        selectedSymbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not any(symbol["symbol"] == selectedSymbol for symbol in symbols):
            return apology("No stock chosen", 400)

        elif not shares:
            return apology("Please enter a number", 400)

        shares = int(shares)

        if shares < 0:
            return apology("Please enter a positive number", 400)

        selectedStock = db.execute("SELECT symbol, quantity FROM purchase_history WHERE user_id = ? AND symbol = ? GROUP BY symbol", session["user_id"], selectedSymbol)

        if not selectedStock:
            return apology("You do not own any shares", 400)

        currentPrice = lookup(selectedSymbol)
        if not currentPrice:
            return apology("Failed to obtain current stock price", 400)

        sellTotal = currentPrice["price"] * shares

        if selectedStock[0]["quantity"] < shares:
            return apology("Not enough shares to sell", 400)

        currentDateTime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sellTotal, session["user_id"])
        db.execute("INSERT INTO purchase_history(user_id, symbol, stock_price, quantity, total_buy, purchase_date) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], selectedSymbol, currentPrice["price"], -shares, -sellTotal, currentDateTime)

        session["message"] = "Sold!"
        return redirect("/")

    return render_template("sell.html", symbols=symbols)


@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    users = db.execute("SELECT username, cash FROM users WHERE id = ?", session["user_id"])
    if request.method == "POST":
        newPassword = request.form.get("password")
        if not newPassword:
            return apology("Please enter a valid password", 400)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(newPassword), session["user_id"])
        session["message"] = "Password changed!"
        return redirect("/")
    # Check if a message is already present
    if "message" in session:
        message = session["message"]
        # Remove the message from the session
        session.pop("message", None)
    else:
        message = None

    return render_template("profile.html", users=users, message=message)
