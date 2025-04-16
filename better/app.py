from flask import Flask, render_template, url_for, request, redirect, session
import mysql.connector
import hashlib
import logging
import os
from datetime import datetime

if os.path.exists('better/logs/report.log'):
    with open('better/logs/report.log', 'w') as file:
        file.close()
    
logging.basicConfig(
    filename='better/logs/report.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
password_hash = hashlib.sha256()
app.secret_key = 'something123'

db = mysql.connector.connect(
    host="",
    user="",
    password="",
    database=""
)
cursor = db.cursor(dictionary=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')

        query = "SELECT * FROM users WHERE email = %s OR username = %s"
        cursor.execute(query, (identifier, identifier))
        user = cursor.fetchone()

        if user:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash == user['password']:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                logging.info(f"User {user['username']} ({user['email']}) logged in successfully")
                return redirect(url_for('user'))
            else:
                logging.warning(f"Incorect password for user {identifier}")
                error_message = "Your password is incorect try again"
        else:
            logging.warning(f"Login attempt for non-existent email: {identifier}")
            error_message = "No user with that email or username"
        
    return render_template("login.html", error_message=error_message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method  == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_hash.update(password.encode())
        hash_password = password_hash.hexdigest()
        query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
        value = (username, email, hash_password)
        try:
            cursor.execute(query, value)
            db.commit()
            print("the register was succesfull")
            logging.info(f"User {username} with email: {email} Registered")
            return redirect(url_for('home'))
        except Exception as e:
            print("something went wrong when updating the database")
            logging.error(f"Error ocured with writing to database: {e}")

    return render_template('login.html')

@app.route('/logout')
def logout():
    user_email = session.get('email', 'Unknown')
    logging.info(f"User {user_email} logged out")
    session.clear()
    return redirect(url_for('home'))

@app.route('/user')
def user():
    if 'user_id' not in session:
        logging.warning("Unauthorized access to /user")
        return redirect(url_for('login'))
    
    username = session.get('username')

    return render_template("user.html", username=username)

@app.route('/user/favorite')
def favorite():
    if 'user_id' not in session:
        logging.warning("Unauthorized access to /user")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    query = """
        SELECT b.id, b.title
        FROM favorites f
        JOIN books b ON f.book_id = b.id
        WHERE f.user_id = %s
    """

    cursor.execute(query, (user_id,))
    fav_books = cursor.fetchall()

    return render_template("favorites.html", fav_books=fav_books)

@app.route('/user/history')
def borrow_history():
    if 'user_id' not in session:
        logging.warning("Unauthorized access to /user")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    query = """
        SELECT b.title, bb.borrowed_at, bb.returned_at
        FROM borrowed_books bb
        JOIN books b ON bb.book_id = b.id
        WHERE bb.user_id = %s
    """
    cursor.execute(query, (user_id,))
    history = cursor.fetchall()
    return render_template("history.html", history=history)

@app.route('/books')
def books():
    query = "SELECT id, title FROM books"
    cursor.execute(query)
    books = cursor.fetchall()
    return render_template("books.html", books=books)

@app.route('/books/<int:book_id>')
def book_details(book_id):
    query = "SELECT * FROM books WHERE id = %s"
    cursor.execute(query, (book_id,))
    book = cursor.fetchone()

    if not book:
        logging.warning(f"Book: {book} was not founf")
        return "Book not found", 404
    
    return render_template("book_details.html", book=book)

@app.route('/books/borrow/<int:book_id>', methods=['POST'])
def borrow_book(book_id):
   if 'user_id' not in session:
        logging.warning("Unauthorized access to /user")
        return redirect(url_for('login'))
   
   user_id = session['user_id']

   check_query = """
    SELECT * FROM borrowed_books
    WHERE user_id = %s AND book_id = %s AND returned_at IS NULL
    """
   cursor.execute(check_query, (user_id, book_id))
   already_borrowed = cursor.fetchone()
   
   if already_borrowed:
       logging.warning(f"User {user_id} tried to borrow book {book_id} again.")
       return "You already borrowed this book"
   
   query = "INSERT INTO borrowed_books (user_id, book_id) VALUES (%s, %s)"
   cursor.execute(query, (user_id, book_id))
   db.commit()
   logging.info(f"User {user_id} borrowed book {book_id}")
   return redirect(url_for('borrow_history'))

@app.route('/books/return/<int:book_id>', methods=['POST'])
def return_book(book_id):
    if 'user_id' not in session:
        logging.warning("Unauthorized access to /user")
        return redirect(url_for('login'))
    
    user_id = session['user_id']

    query = """
        UPDATE borrowed_books
        SET returned_at = %s
        WHERE user_id = %s AND book_id = %s AND returned_at IS NULL
    """
    now = datetime.now()
    cursor.execute(query, (now, user_id, book_id))
    db.commit()
    logging.info(f"User {user_id} returned book {book_id}")
    return redirect(url_for('borrow_history'))
    

@app.route('/search')
def search():
    pass

@app.route('/admin')
def admin_dashboard():
    pass

@app.route('/admin/books/add', methods=['GET', 'POST'])
def add_book():
    pass

@app.route('/admin/books/update/<int:book_id>', methods=['GET', 'POST'])
def update_book(book_id):
    pass

@app.route('/admin/books/remove/<int:book_id>', methods=['GET', 'POST'])
def remove_book():
    pass

@app.route('/about_us')
def about_us():
    pass

@app.route('/faq')
def faq():
    pass

if __name__ == "__main__":
    app.run(debug=True)