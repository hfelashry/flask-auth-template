from flask import Flask, render_template, request, session, redirect, url_for
import bcrypt
import pymongo
import os
import google.generativeai as genai
import markdown

app = Flask(__name__)
app.secret_key = "jhafyBEYDHBF*fhu0_Sd;aspd#Y&*G"

# Database
client = pymongo.MongoClient("mongodb+srv://hamzafelashry12:65uSWsMu0E4eTKkW@notaiq.klloi.mongodb.net/?retryWrites=true&w=majority&appName=NotaIQ")
db = client.get_database('NotaIQ')
auth = db.register

#! Static Page Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

#! Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if 'email' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = request.form.get("name")
        email = request.form.get('email')
        password = request.form.get('password')
        passwordAgain = request.form.get('passwordAgain')

        user_found = auth.find_one({'name': user})
        email_found = auth.find_one({'email': email})
        
        if user_found:
            message = "There is already a user by that name."
            return render_template('register.html', message=message)
        
        if email_found:
            message = 'There is already a different user with that email address.'
            return render_template('register.html', message=message)
        
        if password != passwordAgain:
            message = 'Passwords should match! try again.'
            return render_template('register.html', message=message)
        else:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            auth.insert_one(user_input)

            # Save user details in session after successful registration
            session["email"] = email
            session["name"] = user
            return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = 'Please login to your account'
    
    if "email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        email_found = auth.find_one({"email": email})
        if email_found:
            passwordcheck = email_found['password']
            
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_found["email"]
                session["name"] = email_found["name"]
                return redirect(url_for('dashboard'))
            else:
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    
    return render_template('login.html')

@app.route('/signout')
def signout():
    session.pop('email', None)
    session.pop('name', None)
    return render_template('index.html')

#! User Routes
@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        email = session['email']
        name = session.get('name', 'User')  # Use a default if name not found in session
        return render_template('dashboard.html', name=name, email=email)
    else:
        return redirect(url_for('login'))

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    questions = ''
    if 'email' in session:
        email = session['email']
        name = session.get('name', 'User')  # Use a default if name not found in session
        if request.method == 'POST':
            text = request.form['text_input']
            geminiKey = os.environ["geminiKey"]
            genai.configure(api_key=geminiKey)
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content('With the following notes, create questions so that the student can answer them to study. ' + text)
            text_content = response.candidates[0].content.parts[0].text
            questions = markdown.markdown(text_content)
        return render_template("generate.html", content=questions)
    else:
        return redirect(url_for('login'))

app.run(host="0.0.0.0", port=80, debug=True)
