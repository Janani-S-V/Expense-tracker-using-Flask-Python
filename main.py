from flask import Flask, request, render_template, redirect, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from datetime import datetime
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expense_tracker.db'
app.secret_key = 'the random string'
app.config['FLASK_ADMIN_SWATCH'] = 'Slate'
admin = Admin(app, template_mode='bootstrap4')
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    expenses = db.relationship('Expense', backref='user', lazy=True)
    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

admin.add_view(ModelView(Expense, db.session))

@app.route('/', methods=['GET'])
def homepage():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        expenses = Expense.query.filter_by(user_id=user.id).all()
        return render_template('dashboard.html' , user=user , expenses=expenses)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/')
        else:
            return render_template('login.html', error='Invalid user')
    return render_template('login.html')

@app.route('/dashboard', methods=["GET","POST"])
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        if user:
            expenses = Expense.query.filter_by(user_id=user.id).all()
            return render_template('dashboard.html', user=user, expenses=expenses)
    return redirect('/login')


@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/view_expenses')
def view_expenses():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        if user:
            expenses = Expense.query.filter_by(user_id=user.id).all()
            return render_template('view_expenses.html', user=user, expenses=expenses)
    return redirect('/login')


@app.route('/add_expense', methods=['POST'])
def add_expense():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        if request.method == 'POST':
            amount = float(request.form['amount'])
            description = request.form['description']
            category = request.form['category']

            new_expense = Expense(amount=amount, description=description, category=category, user=user)
            db.session.add(new_expense)
            db.session.commit()
    return redirect('/dashboard')

@app.route('/generate_report')
def generate_report():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        if user:
            expenses = Expense.query.filter_by(user_id=user.id).all()
            total_expenses = sum(expense.amount for expense in expenses)
            expenses_by_category = {}
            for expense in expenses:
                if expense.category in expenses_by_category:
                    expenses_by_category[expense.category] += expense.amount
                else:
                    expenses_by_category[expense.category] = expense.amount


            csv_data = "Category,Amount\n"
            for category, amount in expenses_by_category.items():
                csv_data += f"{category},{amount}\n"

           
            response = Response(csv_data, mimetype='text/csv')
            response.headers['Content-Disposition'] = 'attachment; filename=expense_report.csv'
            return response
    return redirect('/login')


if __name__ =='__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
