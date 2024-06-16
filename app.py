import os
from functools import wraps
import mysql.connector as connector
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from mysqldb import DBConnector

app = Flask(__name__)
application = app
app.config.from_pyfile('config.py')
db_connector = DBConnector(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'
login_manager.login_message_category = 'warning'

def db_operation(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        connection = db_connector.connect()
        try:
            with connection.cursor(named_tuple=True, buffered=True) as cursor:
                result = func(cursor, *args, **kwargs)
                connection.commit()
        except Exception as e:
            connection.rollback()
            print(f"Error in {func.__name__}: {e}") 
            raise e
        return result
    return wrapper

class User(UserMixin):
    def __init__(self, user_id, username, role_id, first_name=None, last_name=None):
        self.id = user_id
        self.username = username
        self.role_id = role_id
        self.first_name = first_name
        self.last_name = last_name

@login_manager.user_loader
def load_user(user_id):
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute("SELECT id, username, role_id, first_name, last_name FROM users WHERE id = %s;", (user_id,))
        user = cursor.fetchone()
    if user is not None:
        return User(user.id, user.username, user.role_id, user.first_name, user.last_name)
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role_id != 1:
            flash('У вас недостаточно прав для этого', 'danger')
            return redirect(request.referrer or url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def moderator_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role_id not in [1, 2]:
            flash('У вас недостаточно прав для этого', 'danger')
            return redirect(request.referrer or url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Главная страница
@app.route('/')
@db_operation
def index(cursor):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    cursor.execute("""
        SELECT books.id, books.title, GROUP_CONCAT(genres.name SEPARATOR ', ') as genres, books.year, 
               COALESCE(ROUND(AVG(reviews.rating), 1), 0) as average_rating, COUNT(reviews.id) as review_count
        FROM books
        LEFT JOIN book_genres ON books.id = book_genres.book_id
        LEFT JOIN genres ON book_genres.genre_id = genres.id
        LEFT JOIN reviews ON books.id = reviews.book_id
        GROUP BY books.id
        ORDER BY books.year DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    books = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) as total FROM books")
    total_books = cursor.fetchone().total

    total_pages = (total_books + per_page - 1) // per_page

    return render_template('index.html', books=books, page=page, total_pages=total_pages)

# Аутентификация
@app.route('/auth', methods=['POST', 'GET'])
@db_operation
def auth(cursor):
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            remember_me = request.form.get('remember_me', None) == 'on'

            cursor.execute(
                "SELECT id, username, role_id, first_name, last_name FROM users WHERE username = %s AND password_hash = SHA2(%s, 256)",
                (username, password)
            )
            user = cursor.fetchone()

            if user:
                flash('Авторизация прошла успешно', 'success')
                user_obj = User(user.id, user.username, user.role_id, user.first_name, user.last_name)
                login_user(user_obj, remember=remember_me)
                next_url = request.args.get('next', url_for('index'))
                return redirect(next_url)
            flash('Невозможно аутентифицироваться с указанными логином и паролем', 'danger')
        return render_template('auth.html')
    except Exception as e:
        print(f"Error in auth route: {e}")
        abort(500)

# Профиль пользователя (заглушка)
@app.route('/profile')
@login_required
def profile():
    return "Профиль пользователя (в разработке)"

# Выход из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('index'))

# Добавление книги (администратор)
@app.route('/add_book', methods=['GET', 'POST'])
@login_required
@admin_required
@db_operation
def add_book(cursor):
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        year = request.form['year']
        publisher = request.form['publisher']
        author = request.form['author']
        pages = request.form['pages']
        cover_id = request.form['cover_id']
        
        cursor.execute("""
            INSERT INTO books (title, description, year, publisher, author, pages, cover_id) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (title, description, year, publisher, author, pages, cover_id))
        flash('Книга успешно добавлена', 'success')
        return redirect(url_for('index'))
    return render_template('add_book.html')

# Редактирование книги (администратор и модератор)
@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
@login_required
@db_operation
def edit_book(cursor, book_id):
    if current_user.role_id not in [1, 2]:
        flash('У вас недостаточно прав для выполнения данного действия', 'danger')
        return redirect(url_for('index'))

    cursor.execute("SELECT * FROM books WHERE id = %s", (book_id,))
    book = cursor.fetchone()
    if not book:
        flash('Книга не найдена', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        year = request.form['year']
        publisher = request.form['publisher']
        author = request.form['author']
        pages = request.form['pages']
        cover_id = request.form['cover_id']
        
        cursor.execute("""
            UPDATE books 
            SET title=%s, description=%s, year=%s, publisher=%s, author=%s, pages=%s, cover_id=%s 
            WHERE id=%s
        """, (title, description, year, publisher, author, pages, cover_id, book_id))
        flash('Книга успешно отредактирована', 'success')
        return redirect(url_for('index'))
    return render_template('edit_book.html', book=book)

# Удаление книги (администратор)
@app.route('/delete_book/<int:book_id>', methods=['POST'])
@login_required
@admin_required
@db_operation
def delete_book(cursor, book_id):
    cursor.execute("SELECT title FROM books WHERE id = %s", (book_id,))
    book = cursor.fetchone()
    if not book:
        flash('Книга не найдена', 'danger')
        return redirect(url_for('index'))

    cursor.execute("DELETE FROM books WHERE id = %s", (book_id,))
    flash(f'Книга "{book.title}" успешно удалена', 'success')
    return redirect(url_for('index'))

# Просмотр книги
@app.route('/view_book/<int:book_id>')
@db_operation
def view_book(cursor, book_id):
    cursor.execute("""
        SELECT books.*, GROUP_CONCAT(genres.name SEPARATOR ', ') as genres, 
               COALESCE(ROUND(AVG(reviews.rating), 1), 0) as average_rating
        FROM books
        LEFT JOIN book_genres ON books.id = book_genres.book_id
        LEFT JOIN genres ON book_genres.genre_id = genres.id
        LEFT JOIN reviews ON books.id = reviews.book_id
        WHERE books.id = %s
        GROUP BY books.id
    """, (book_id,))
    book = cursor.fetchone()
    if not book:
        flash('Книга не найдена', 'danger')
        return redirect(url_for('index'))

    cursor.execute("""
        SELECT reviews.*, users.username 
        FROM reviews 
        LEFT JOIN users ON reviews.user_id = users.id 
        WHERE reviews.book_id = %s
    """, (book_id,))
    reviews = cursor.fetchall()
    
    user_review = None
    if current_user.is_authenticated:
        cursor.execute("""
            SELECT reviews.*, users.username 
            FROM reviews 
            LEFT JOIN users ON reviews.user_id = users.id 
            WHERE reviews.book_id = %s AND reviews.user_id = %s
        """, (book_id, current_user.id))
        user_review = cursor.fetchone()
        
    return render_template('view_book.html', book=book, reviews=reviews, user_review=user_review)

# Добавление рецензии (пользователь)
@app.route('/add_review/<int:book_id>', methods=['GET', 'POST'])
@login_required
@db_operation
def add_review(cursor, book_id):
    cursor.execute("""
        SELECT * FROM reviews 
        WHERE book_id = %s AND user_id = %s
    """, (book_id, current_user.id))
    review = cursor.fetchone()
    
    if review:
        flash('Вы уже написали рецензию на эту книгу', 'warning')
        return redirect(url_for('view_book', book_id=book_id))
    
    if request.method == 'POST':
        rating = request.form['rating']
        text = request.form['text']
        
        cursor.execute("""
            INSERT INTO reviews (book_id, user_id, rating, text) 
            VALUES (%s, %s, %s, %s)
        """, (book_id, current_user.id, rating, text))
        flash('Рецензия успешно добавлена', 'success')
        return redirect(url_for('view_book', book_id=book_id))
    return render_template('add_review.html', book_id=book_id)

# Редактирование рецензии (модератор или администратор)
@app.route('/edit_review/<int:review_id>', methods=['GET', 'POST'])
@login_required
@moderator_or_admin_required
@db_operation
def edit_review(cursor, review_id):
    cursor.execute("SELECT * FROM reviews WHERE id = %s", (review_id,))
    review = cursor.fetchone()
    if not review:
        flash('Рецензия не найдена', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        rating = request.form['rating']
        text = request.form['text']
        
        cursor.execute("""
            UPDATE reviews 
            SET rating=%s, text=%s 
            WHERE id=%s
        """, (rating, text, review_id))
        flash('Рецензия успешно отредактирована', 'success')
        return redirect(url_for('view_book', book_id=review.book_id))
    return render_template('edit_review.html', review=review)

if __name__ == '__main__':
    app.run(debug=True)