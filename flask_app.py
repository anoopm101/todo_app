import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# Initialize the Flask application
# We'll rename this file to app.py, but for the diff, we'll use the original name.
app = Flask(__name__)

# --- Database Configuration ---
# Get the absolute path for the database file
basedir = os.path.abspath(os.path.dirname(__file__))
# Set the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'todo.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# A secret key is required to use sessions, which we need for PIN authentication.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-super-secret-key-you-should-change')

# Initialize the database with the app
db = SQLAlchemy(app)

# --- Application Constants ---
# It's best practice to set your PIN as an environment variable.
# We'll use '1234' as a default if it's not set.
APP_PIN = os.environ.get('APP_PIN', '5112') # Change '8675' to your desired PIN

# --- Database Models ---
class Todo(db.Model):
    __tablename__ = 'todo' # Explicitly name the table
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    priority = db.Column(db.String(10), default='Normal', nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Workout(db.Model):
    __tablename__ = 'workout' # Explicitly name the table
    id = db.Column(db.Integer, primary_key=True)
    exercise = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<Todo {self.id}>'

# --- Create the database ---
# This ensures the database tables are created based on your models
with app.app_context():
    db.create_all()

# --- Routes ---

@app.route("/pin", methods=["GET", "POST"])
def enter_pin():
    if request.method == "POST":
        entered_pin = request.form.get("pin")
        if entered_pin == APP_PIN:
            session['authenticated'] = True
            return redirect(url_for("index"))
        else:
            flash("Incorrect PIN. Please try again.")
    # If already authenticated, just go to the index
    if session.get('authenticated'):
        return redirect(url_for('index'))
    return render_template("pin.html")

@app.route("/logout")
def logout():
    session.pop('authenticated', None) # Clear the session
    flash("You have been logged out.")
    return redirect(url_for('enter_pin'))

@app.route("/", methods=["GET", "POST"])
def index():
    # Protect this route: if not authenticated, redirect to PIN page
    if not session.get('authenticated'):
        return redirect(url_for('enter_pin'))

    if request.method == "POST":
        todo_content = request.form.get("content")
        todo_priority = request.form.get("priority", "Normal")
        if todo_content:
            new_todo = Todo(content=todo_content, priority=todo_priority)
            db.session.add(new_todo)
            db.session.commit()
        # Redirect back to the index page after adding a task
        return redirect(url_for("index"))

    # Query todos for the current user only
    priority_order = case(
        (Todo.priority == 'High', 0),
        else_=1
    )
    todos = Todo.query.order_by(priority_order, Todo.completed, Todo.id).all()
    return render_template("index.html", todos=todos)

@app.route("/complete/<int:todo_id>")
def complete(todo_id):
    """
    Toggles the completed status of a task.
    """
    # Protect this route as well
    if not session.get('authenticated'):
        return redirect(url_for('enter_pin'))

    todo_to_complete = db.get_or_404(Todo, todo_id)
    todo_to_complete.completed = not todo_to_complete.completed
    db.session.commit()
    return redirect(url_for("index"))