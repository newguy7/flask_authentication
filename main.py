
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug import security


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

#Configuring the Flask-Login's LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# provide a user_loader callback
# used to reload the user object from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User,user_id)


# CREATE TABLE IN DB
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
 
 
with app.app_context():
    db.create_all()



@app.route('/')
def home():         
    return render_template("index.html", logged_in = current_user.is_authenticated)
 


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':    
        email = request.form['email']
        result = db.session.execute(db.select(User).where(User.email == email))
        user_result = result.scalar()
        if user_result:
            # user already exists        
            flash("Email already registered. Redirecting to the login page.")
            return redirect(url_for('login'))
        name = request.form['name']
        password = request.form['password']
        password_hash = security.generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
        user = User(email=email,name=name,password=password_hash)
        db.session.add(user)
        db.session.commit()

        # Log in and authenticate user after adding details to the database
        login_user(user)

        return redirect(url_for("secrets"))
    return render_template("register.html",logged_in = current_user.is_authenticated)
    


@app.route('/login',methods=["GET", "POST"])
def login():
    
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user by email entered
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar() 

        # check stored email against entered email
        if not user:
            flash("Email entered does not match. Try again.")
            return redirect(url_for('login'))

        # check stored password hash against entered password hashed
        elif not check_password_hash(user.password, password):
            flash("Password incorrect. Please try again.")
            return redirect(url_for('login'))
        else:            
            login_user(user)
            return redirect(url_for('secrets'))


    return render_template("login.html",logged_in = current_user.is_authenticated)


# Only logged in users can access the route
@app.route('/secrets')
@login_required
def secrets():       
    return render_template("secrets.html",name=current_user.name,logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

# Need to be logged in to download the file
@app.route('/download')
@login_required
def download():
    return send_from_directory(
        directory='static/files', path="secret.pdf", as_attachment=False
    )


if __name__ == "__main__":
    app.run(debug=True)
