from flask import Flask, render_template, request, session, redirect, url_for
from bson.objectid import ObjectId
import bcrypt
import pymongo
import os
import markdown
import json
from groq import Groq

#! Recaptcha
class ReCaptcha():
    SECRET_KEY = 'jhafyBEYDHBF*fhu0_Sd;aspd#Y&*G' 
    RECAPTCHA_USE_SSL= False
    RECAPTCHA_PUBLIC_KEY = '6LdjPC8qAAAAAMeH4k8TvOR4F1cWWYFxaxNhSRdw' # google generated
    RECAPTCHA_PRIVATE_KEY = '6LdjPC8qAAAAAHPELHEQE8MnzI8Z7QEZwuxxHX03' # google generated
    RECAPTCHA_DATA_ATTRS = {'theme': 'light'}

def is_human(captcha_response):
    payload = {'response': captcha_response, 'secret': private_key}
    response = post("https://www.google.com/recaptcha/api/siteverify", data=payload)
    response_text = json.loads(response.text)
    return response_text['success']

pub_key = ReCaptcha.RECAPTCHA_PUBLIC_KEY
private_key = ReCaptcha.RECAPTCHA_PRIVATE_KEY

app = Flask(__name__)
app.config.from_object(ReCaptcha)
app.secret_key = "jhafyBEYDHBF*fhu0_Sd;aspd#Y&*G"

# Database
client = pymongo.MongoClient("mongodb+srv://hamzafelashry12:65uSWsMu0E4eTKkW@notaiq.klloi.mongodb.net/?retryWrites=true&w=majority&appName=NotaIQ")
db = client.get_database('NotaIQ')
auth = db.register
task_record = db.tasks

#! Groq
groqClient = Groq(
    api_key= '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'
)

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
            message = 'Passwords should match! Try again.'
            return render_template('register.html', message=message)
        
        captcha_response = request.form['g-recaptcha-response']
        print(captcha_response)
        if is_human(captcha_response):
            # If ReCaptcha passes, proceed with hashing the password and registering the user
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            auth.insert_one(user_input)

            # Save user details in session after successful registration
            session["email"] = email
            session["name"] = user
            return redirect(url_for('dashboard'))
        else:
            # If ReCaptcha fails, return an error message
            message = 'ReCaptcha failed, please try again.'
            return render_template('register.html', message=message)
    
    return render_template('register.html', pub_key=pub_key)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = 'Please login to your account'
    
    if "email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Verify reCAPTCHA
        if not is_human(recaptcha_response):
            message = 'reCAPTCHA verification failed. Please try again.'
            return render_template('login.html', message=message, pub_key=pub_key)

        # Check email and password
        email_found = auth.find_one({"email": email})
        if email_found:
            passwordcheck = email_found['password']
            
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_found["email"]
                session["name"] = email_found["name"]
                return redirect(url_for('dashboard'))
            else:
                message = 'Wrong password'
                return render_template('login.html', message=message, pub_key=pub_key)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message, pub_key=pub_key)
    
    return render_template('login.html', pub_key=pub_key)

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
            chat_completion = groqClient.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": "With the following notes, please create questions so that the student can answer and to learn the topic better." + text,
                    }
                ],
                model="llama3-8b-8192",
            )
            text_content = chat_completion.choices[0].message.content
            questions = markdown.markdown(text_content)
        return render_template("generate.html", content=questions)
    else:
        return redirect(url_for('login'))

todos = []

# Show tasks for a specific user
@app.route('/tasks', methods=['GET'])
def tasks():
    if 'email' in session:
        user_email = session['email']
        todos = list(task_record.find({'email': user_email}))
        return render_template('tasks.html', todos=todos)
    return redirect(url_for('login'))

@app.route('/tasks/add', methods=['POST'])
def add():
    task_text = request.form.get('inputTodo').strip()
    if task_text:
        task_record.insert_one({'task': task_text, 'done': False, 'email': session['email']})
    return redirect(url_for('tasks'))

@app.route('/tasks/check/<task_id>', methods=['POST'])
def check(task_id):
    task_record.update_one({'_id': ObjectId(task_id)}, {'$set': {'done': not task['done']}})
    return '', 204

@app.route('/tasks/delete/<task_id>', methods=['GET'])
def delete(task_id):
    task_record.delete_one({'_id': ObjectId(task_id), 'email': session['email']})
    return redirect(url_for('tasks'))

@app.route('/tasks/edit/<task_id>', methods=['POST'])
def edit(task_id):
    new_task = request.form['todo']
    task_record.update_one({'_id': ObjectId(task_id)}, {'$set': {'task': new_task}})
    return redirect(url_for('tasks'))

@app.route('/discord')
def discord():
    return redirect('https://discord.gg/vABM9PdWvh')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=True)
