from flask import Flask, render_template,url_for,request, redirect,flash,session, send_file
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from functools import wraps
from datetime import datetime
from flask_mail import Mail, Message
import os
from werkzeug.utils import secure_filename
from flask_moment import Moment         # ext for time and date
import random

from PIL import Image
from flask_compress import Compress

import csv
import io
import re

app = Flask(__name__)

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.schooldb  #databse name => testdb

app.secret_key = ''
bcrypt = Bcrypt(app)

# Configure Compressing
COMPRESS_MIMETYPES = ['text/html', 'text/css', 'text/xml', 'application/json', 'application/javascript']
COMPRESS_LEVEL = 6
COMPRESS_MIN_SIZE = 500

def configure_app(app):
    Compress(app)

#current datatime
now = datetime.utcnow()
moment = Moment(app)        #timedate
moment.init_app(app)

#mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
mail = Mail(app)

#file upload
path1 = os.path.abspath('C:/Users/Administrator/PycharmProjects/gchs_web_flask/static/images/gallery')    #for gallery
app.config['UPLOAD_PATH'] = path1
path1_1 = os.path.abspath('C:/Users/Administrator/PycharmProjects/gchs_web_flask/static/images/gallery/thumb')    #for thumb gallery
app.config['UPLOAD_PATH_THUMB'] = path1_1
SIZE_300 = (300,300)
SIZE_1200 = (1200,1200)
SIZE_700 = (700,700)

path2 = os.path.abspath('C:/Users/Administrator/PycharmProjects/gchs_web_flask/static/images/profile')    #for profile pictures
app.config['UPLOAD_FOLDER'] = path2

path3 = os.path.abspath('C:/Users/Administrator/PycharmProjects/gchs_web_flask/static/images/uploads')    #for others
app.config['UPLOAD'] = path3

#for images
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#for csv upload
ALLOWED_DATA_EXTENSIONS = set(['csv'])
def allowed_data_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_DATA_EXTENSIONS

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'username' in session:
            return f(*args, **kwargs)
        else:
            flash('Login required, please login', 'danger')
            return redirect(url_for('login'))
    return wrap

def is_already_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'username' in session:
            #flash('You are already logged in', 'danger')
            return redirect(url_for('home'))
        else:
            return f(*args, **kwargs)
    return wrap

@app.route('/')
def index():
    return render_template('loader.html')

@app.route('/home')
def home():
    updates = db.updates.find().sort('id',-1)
    return render_template('index.html', updates = updates)


@app.route('/gallery/')
def gallery():
    photos = db.gallery.find({'type':'public'}).sort('id', -1)
    pvt_photos = db.gallery.find().sort('id', -1)
    return render_template('gallery.html', photos = photos, pvt_photos = pvt_photos, now = now)

@app.route('/gallery_photo_upload', methods = ['GET','POST'])
@is_logged_in
def gallery_photo_upload():

        if request.method == 'POST' and 'photos' in request.files:
            for f in request.files.getlist('photos'):

                if not allowed_file(f.filename):
                    flash('one of more files not uploaded, file type not allowed', 'danger')
                    continue

                rn = str(random.randint(1, 10000))
                i = Image.open(f)
                i.thumbnail(SIZE_300)
                i.save(os.path.join(app.config['UPLOAD_PATH_THUMB'], rn+f.filename))
                j = Image.open(f)
                j.thumbnail(SIZE_1200)
                j.save(os.path.join(app.config['UPLOAD_PATH'], rn + f.filename))

                id = str(db.gallery.find().count())
                usr = db.users.find_one({'email':session['username']})

                if usr['type']=='admin':
                    type='public'
                else:
                    type = 'private'

                db.gallery.insert({'id':'p'+id,'img':'images/gallery/'+rn+f.filename,'img_thumb':'images/gallery/thumb/'+rn+f.filename, 'img_name':rn+f.filename, 'upd_by':{'user':session['username'], 'name':usr['fname']+' '+usr['lname']},'type':type,'date':now})

            flash('Uploaded successfully', 'success')
            return redirect(url_for('gallery'))
        flash('Something went wrong','danger')
        return redirect(url_for('gallery'))


@app.route('/delete_photo', methods = ['POST'])
@is_logged_in
def delete_photo():
        photo_id = request.values.get('photo_id')
        db.gallery.remove({'img_name':photo_id})
        os.remove(os.path.join(app.config['UPLOAD_PATH'],photo_id))
        os.remove(os.path.join(app.config['UPLOAD_PATH_THUMB'], photo_id))
        flash('Deleted successfully','success')
        return redirect(url_for('gallery'))

@app.route('/admin/')
@is_logged_in
def admin():
    if session['user_type'] == 'admin':
        return render_template('admin.html')
    return redirect(url_for('index'))


@app.route('/list/')
@is_logged_in
def list():
    alumni = db.users.find().sort('usrid',-1)
    return render_template('list.html', alumni = alumni)


@app.route('/add_alumni/')
@is_logged_in
def add_alumni():
    if session['user_type'] == 'admin':
        return render_template('add_alumni.html',now = now)
    return redirect(url_for('index'))

@app.route('/profile/<userid>')
@is_logged_in
def profile(userid):
    user_data = db.users.find_one({'email':userid})
    return render_template('profile.html', data = user_data)

@app.route('/update_profile/<user>')
@is_logged_in
def update_profile(user):
    user_data = db.users.find_one({'email':user})
    return render_template('update_profile.html', data = user_data, now = now)

@app.route('/upload/<user>', methods = ['GET','POST'])
@is_logged_in
def upload(user):
    if request.method == 'POST':
        # check if the post request has the file part
        if 'image' not in request.files:
            flash('No file part','danger')
            return redirect(url_for('update_profile', user = user))
        file = request.files['image']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file','danger')
            return redirect(url_for('update_profile', user = user))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            rn = str(random.randint(1000, 10000))
            i = Image.open(file)
            i.thumbnail(SIZE_700)
            i.save(os.path.join(app.config['UPLOAD_FOLDER'], rn+filename))
            this_user = db.users.find_one({'email':user})
            is_img = request.values.get('img')
            if is_img != '':
                photo_id = this_user['p_img_name']
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo_id))
            db.users.update({'email':user},{'$set':{'p_img':'images/profile/'+rn+filename,'p_img_name':rn+filename}})
            flash('Uploaded successfully','success')
            return redirect(url_for('profile', userid = user))

    flash('Something went wrong, please try again','danger')
    return redirect(url_for('update_profile', user = user))

@app.route('/signup/')
@is_already_logged_in
def signup():
        return render_template('signup.html', now = now)

@app.route('/signup_user', methods = ['POST'])
def signup_user():
    if request.method == 'POST':
        users = db.users
        email = request.values.get("email")
        existing_user = db.users.find_one({"email":email})

        if existing_user is None:
            count = db.users.find().count() + 1
            fname = request.values.get("first_name").capitalize()
            lname = request.values.get("last_name").capitalize()
            contact = request.values.get("contact")
            batch = request.values.get("batch")
            user_type = request.values.get('type')
            pw = request.values.get("password")
            pw_hash = bcrypt.generate_password_hash(pw,10)
            users.insert({"usrid":str(count)+'a',"fname":fname, "lname":lname,"batch":batch,"contact":contact,"email":email,"pass":pw_hash,"type":user_type,"join_date":now,"p_img_name":""})

            msg = Message('Welcome, Registration successfull', sender='contact.gchspune@gmail.com', recipients=[email])
            msg.html = "Hello "+fname + ' '+lname+"!"+"<br><br>You have been successfully registered to gchspune.com<br>Your login credentials are : <br> Username : "+email+"<br>Password : "+pw+"<br>Login here : www.gchspune.com/login</a>"
            msg.body = msg.html
            mail.send(msg)
            return render_template('homepage/reg_message.html')
        flash('User already exists','danger')
        return redirect(url_for('signup'))
    return redirect(url_for('signup'))

@app.route('/register_user', methods = ['POST'])
def register():
    if request.method == 'POST':
        users = db.users
        email = request.values.get("email")
        existing_user = db.users.find_one({"email":email})

        if existing_user is None:
            count = db.users.find().count() + 1
            fname = request.values.get("first_name").capitalize()
            lname = request.values.get("last_name").capitalize()
            contact = request.values.get("contact")
            batch = request.values.get("batch")
            user_type = request.values.get('type')
            pw = str(random.randint(30000,9000000))
            pw_hash = bcrypt.generate_password_hash(pw,10)
            users.insert({"usrid":str(count)+'a',"fname":fname, "lname":lname,"batch":batch,"contact":contact,"email":email,"pass":pw_hash,"type":user_type,"join_date":now,"p_img_name":""})

            msg = Message('Welcome, Registration successfull', sender='contact.gchspune@gmail.com', recipients=[email])
            msg.html = "Hello "+fname + ' '+lname+"!"+"<br><br>You have been successfully registered to gchspune.com<br>Your login credentials are : <br> Username : "+email+"<br>Password : "+pw+"<br>Login here : www.gchspune.com/login</a>"
            msg.body = msg.html
            mail.send(msg)
            flash('Registered Successfully','success')
            return redirect(url_for('add_alumni'))
        flash('User already exists','danger')
        return redirect(url_for('add_alumni'))
    return redirect(url_for('index'))



@app.route('/change_type/<type>/<user>')
@is_logged_in
def change_type(type,user):
    if session['user_type'] == 'admin':
        u = db.users.find_one({'email':user})
        if u['usrid'] == '1a':
            flash('Not authorised', 'danger')
            return redirect(url_for('profile', userid=user))
        db.users.update({'email':user},{'$set':{'type':type}})
        flash('User type changed successfully','success')
        return redirect(url_for('profile',userid = user))
    return redirect(url_for('index'))


@app.route('/update_personal/<user>', methods = ['POST'])
@is_logged_in
def update_personal(user):
    if session['user_type'] == 'admin' or session['username'] == user:
        if request.method == 'POST':
            fname = request.values.get("first_name")
            lname = request.values.get("last_name")
            contact = request.values.get("contact")
            batch = request.values.get("batch")
            email = request.values.get("email")
            db.users.update({'email':user},{'$set':{"fname":fname, "lname":lname,"batch":batch,"contact":contact,"email":email}})
            if email != user:
                flash('successfull, please login again with newly updated email', 'success')
                return redirect(url_for('logout'))
            flash('Updated successfully','success')
            return redirect(url_for('profile',userid = email))

        return redirect(url_for('login'))
    return redirect(url_for('login'))


@app.route('/update_professional/<user>', methods = ['POST'])
@is_logged_in
def update_professional(user):
    if session['user_type'] == 'admin' or session['username'] == user:
        if request.method == 'POST':
            profession = request.values.get("profession")
            c_name = request.values.get("name")
            loc = request.values.get("loc")
            db.users.update({'email':user},{'$set':{"profession":profession,"c_name":c_name,"loc":loc}})
            flash('Thank you, details updated successfully','success')
            return redirect(url_for('profile',userid = user))
        return redirect(url_for('login'))
    return redirect(url_for('login'))


@app.route('/login/')
@is_already_logged_in
def login():
    return render_template('login.html')

@app.route('/login_user', methods = ['POST'])
@is_already_logged_in
def login_user():
    if request.method == 'POST':
        login_user = db.users.find_one({"email":request.values.get("username")})
        if login_user and bcrypt.check_password_hash(login_user["pass"], request.values.get("password")) :
            session['user_type'] = login_user['type']
            session['username'] = login_user['email']
            session['fname'] = login_user['fname']
            if session["user_type"] == "admin":
                return redirect(url_for('admin'))
            return redirect(url_for('profile',userid = session['username']))

        flash('invalid username or password','danger')
        return redirect(url_for('login'))
    return redirect(url_for('index'))

@app.route('/delete/<user>')
@is_logged_in
def delete(user):
    if session['user_type'] == 'admin':
        if user == session['username']:       #if user is admin then restrict
            flash('Not authorised to delete','danger')
            return redirect(url_for('list'))
        db.users.remove({'email':user})
        flash('User deleted','success')
        return redirect(url_for('list'))
    return redirect(url_for('index'))

@app.route('/changePass', methods = ['post'])
@is_logged_in
def changePass():
    login_user = db.users.find_one({'email': session['username']})
    if bcrypt.check_password_hash(login_user["pass"], request.values.get("c_pass")):
        pw_hash = bcrypt.generate_password_hash(request.values.get("n_pass"))
        db.users.update({'email':login_user['email']},{'$set':{'pass':pw_hash}})
        flash('Password changed successfully, Login Again','success')
        return redirect(url_for('logout'))
    flash('Wrong current password, try again','danger')
    return redirect(url_for('update_profile', user = session['username']))

@app.route('/forgotPass',methods = ['POST'])
def forgotPass():
    if request.method == 'POST':
        email = request.values.get('email')
        exists = db.users.find_one({'email':email})
        if exists:
            rn = str(random.randint(10000, 900000000))
            db.users.update({'email':email},{'$set':{'token':rn}})
            msg = Message('Password Reset Link', sender='techalpha540@gmail.com', recipients=[email])
            msg.html = 'Hello '+email+'<br><p>Your account password reset link is : <br>  http://127.0.0.1:5000/resetPass/'+rn
            msg.body = msg.html
            mail.send(msg)
            flash('Reset link sent your mail', 'info')
            return redirect(url_for('login'))
        flash('Unable to reset password, please contact institute','danger')
        return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/resetPass/<pass_token>')
def resetPass(pass_token):
    exists = db.users.find_one({'token':pass_token})
    if exists:
        return render_template('resetPass.html', token = pass_token)
    return '<h1>Invalid link</h1>'

@app.route('/reset/<token>', methods = ['post'])
def reset(token):
    if request.method == 'POST':
        user = db.users.find_one({'token': token})
        if user:
            pw_hash = bcrypt.generate_password_hash(request.values.get("n_pass"))
            db.users.update({'email': user['email']}, {'$set': {'pass': pw_hash}})
            db.users.update({'email': user['email']}, {'$unset': {'token': 1}})
            flash('Password changed successfully, please login here','success')
            return redirect(url_for('login'))
        return 'Ha Ha.. You caught!'
    return 'Ha Ha.. You caught! This may lead to prison under the Computer Fraud and Abuse Act (CFAA).'

@app.route('/logout/')
@is_logged_in
def logout():
    session.pop('username',None)
    session.pop('user_type',None)
    session.pop('fname',None)
    return redirect(url_for('login'))

#Home page templates
@app.route('/banner')
@is_logged_in
def banner():
    if session['user_type'] == 'admin':
        data = db.homepage.find()
        return render_template('/homepage/banner.html', data = data)
    return redirect('index')

@app.route('/updates')
@is_logged_in
def updates():
    if session['user_type'] == 'admin':
        data = db.updates.find().sort('id',-1)
        return render_template('/homepage/updates.html', data = data)
    return redirect('index')

@app.route('/add_update', methods=['GET','POST'])
@is_logged_in
def add_update():
    if session['user_type'] == 'admin':
        if request.method == 'POST':
            rn = str(random.randint(1000, 10000))
            file = request.files['image']
            if file:
                filename = secure_filename(file.filename)
                i = Image.open(file)
                i.thumbnail(SIZE_700)
                i.save(os.path.join(app.config['UPLOAD'], rn + filename))
            update_id = db.updates.find().count()+1
            title = request.values.get('title')
            desc = request.values.get('desc')
            if file:
                db.updates.insert({'id':str(update_id)+'a','title':title,'desc':desc,'img':'images/uploads/' + rn + filename, 'img_name': rn + filename})
            else:
                db.updates.insert({'id': str(update_id)+'a', 'title': title, 'desc': desc})

            flash('Update added successfully','success')
            return redirect(url_for('updates'))

        return redirect(url_for('updates'))
    return redirect('index')



@app.route('/modify_update', methods=['POST'])
@is_logged_in
def modify_update():
    # update_id = request.values.get('update_id')
    # return update_id
    if session['user_type'] == 'admin':
        if request.method == 'POST':
            title = request.values.get('mtitle')
            desc = request.values.get('mdesc')
            update_id = request.values.get('update_id')
            db.updates.update({'id': update_id},{'$set':{'title': title,'desc':desc}})
            flash('Updated successfully','success')
            return redirect(url_for('updates'))
        return redirect(url_for('updates'))
    return redirect('index')


@app.route('/delete_update/<update_id>/<uid>')
@is_logged_in
def delete_update(update_id,uid):
    if session['user_type'] == 'admin':
        if update_id != 'no_img':
            os.remove(os.path.join(app.config['UPLOAD'], update_id))
            db.updates.remove({'img_name': update_id})
        db.updates.remove({'id': uid})
        flash('Update deleted successfully','info')
        return redirect(url_for('updates'))
    return redirect(url_for('index'))

@app.route('/download_data')
@is_logged_in
def download_data():
    return render_template('download_data.html', now=now)

@app.route('/download', methods=['POST'])
@is_logged_in
def download():
    if request.method == 'POST':
        with open('files/data.csv','w',newline ='') as new_file:
            new_file.truncate()
            writer = csv.writer(new_file)
            batch = request.values.get('batch')
            if batch is not '':
                data = db.users.find({'$and':[{'type': 'alumni'},{'batch':batch}]})
                writer.writerow(['Data of batch '+batch])
                writer.writerow('')
                writer.writerow(['Name','Contact','Email'])
                for d in data:
                    writer.writerow([d['fname']+' '+d['lname'],d['contact'],d['email']])
            else:
                data = db.users.find({'type': 'alumni'})
                writer.writerow(['Data of Garrison Alumni'])
                writer.writerow(['Name', 'Batch', 'Contact', 'Email'])
                writer.writerow('')
                for d in data:
                    writer.writerow([d['fname'] + ' ' + d['lname'], d['batch'], d['contact'], d['email']])

        my_file = 'files/data.csv'
        return send_file(my_file, as_attachment=True)
    return redirect(url_for('index'))


@app.route('/upload_file', methods=['GET','POST'])
@is_logged_in
def upload_file():
    if session['user_type']=='admin':
        if request.method == 'POST':
            f = request.files['datafile']
            if not allowed_data_file(f.filename):
                flash('Invalid file type, only .csv extension allowed', 'danger')
                return redirect(url_for('add_alumni'))
            stream = io.StringIO(f.stream.read().decode("UTF8"))
            csv_input = csv.DictReader(stream)
            users_added=0
            line=1
            errors = {}             #dictionary to save errors
            count = db.users.find().count()
            for data in csv_input:
                line=line+1
                #check for required fields
                if not (data['first_name'] and data['last_name'] and data['email']):
                    errors[line] = "Data missing"
                    continue
                # check for validation
                if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", data['email']):
                    errors[line] = "Invalid email"
                    continue
                # check for duplicate account
                if db.users.find_one({'email':data['email']}):
                    errors[line] = "user already exists"
                    continue

                users_added = users_added + 1
                count = count + 1
                db.users.insert({'usrid':str(count)+'a','fname':data['first_name'],'lname':data['last_name'],'email':data['email'],'batch':data['batch'],'contact':data['contact_no'],'type':'alumni'})

            flash(str(users_added)+' new User/s added successfully','info')
            return render_template('others/csv_result.html',errors=errors)

        return redirect(url_for(index))
    return redirect(url_for(index))



@app.route('/download_sample/<file>')
@is_logged_in
def download_sample(file):
    if session['user_type'] == 'admin':
        my_file = 'files/'+file
        return send_file(my_file, as_attachment=True)
    return redirect(url_for('index'))


if __name__ == '__main__':

    app.jinja_env.cache = {}
    app.run(debug=True)
