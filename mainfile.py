from flask import Flask, render_template,request,redirect,url_for,flash
import os,json,math
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, logout_user, login_required, current_user
from flask_dance.contrib.github import make_github_blueprint,github
from flask_mail import Mail,Message
from datetime import datetime
from werkzeug.utils import secure_filename
from wtforms import ValidationError

local_server = True
with open('config.json', 'r') as c:
    params = json.load(c)["params"]

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['UPLOAD_FOLDER'] = params['upload_location']

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

#github configuration
github_blueprint=make_github_blueprint(client_id='your-client-id',client_secret='your-secret-key')
app.register_blueprint(github_blueprint,url_prefix='/github_login')

#facebook configuration
app.config['SOCIAL_FACEBOOK'] = {
    'consumer_key': 'facebook app id',
    'consumer_secret': 'facebook app secret'
}
#google configuration
app.config['SOCIAL_GOOGLE'] = {
    'consumer_key': 'xxxx',
    'consumer_secret': 'xxxx'
}
app.config['SECURITY_POST_LOGIN'] = '/profile'

app.config.update(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = '465',
    MAIL_USE_SSL = True,
    MAIL_USERNAME = params['gmail-user'],
    MAIL_PASSWORD=  params['gmail-password']
)

mail=Mail(app)

if(local_server):
    app.config['SQLALCHEMY_DATABASE_URI'] = params["local_uri"]
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = params["prod_uri"]

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
Migrate(app,db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

###################################################

class Register(db.Model):

    sno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(20), nullable=False)
    phone_num = db.Column(db.String(12), nullable=False)
    paas = db.Column(db.String(120), nullable=False)
    profile_image = db.Column(db.String(20), default='default_profile.png')
    post1 = db.relationship('Posts', backref='register', lazy=True)

    def get_token(self, expiration=1800):
        s = Serializer(app.config['SECRET_KEY'], expiration)
        return s.dumps({'user': self.sno}).decode('utf-8')


    @staticmethod
    def verify_token(token):
       s = Serializer(app.config['SECRET_KEY'])
       try:
         data = s.loads(token)
       except:
        return None
       sno = data.get('user')
       if sno:
        return Register.query.get(sno)
       return None

class Posts(db.Model):
     sno = db.Column(db.Integer, primary_key=True)
     user_id = db.Column(db.Integer, db.ForeignKey('register.sno'),nullable=False)
     title = db.Column(db.String(80), nullable=False)
     tagLine = db.Column(db.String(100), nullable=False)
     slug = db.Column(db.String(21), nullable=False)
     content = db.Column(db.String(200), nullable=False)
     date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())

db.create_all()
##############################################################################################################################

@login_manager.user_loader
def load_user(user_id):
     # since the user_id is just the primary key of our user table, use it in the query for the user
     return Register.query.get(user_id)

@app.route("/")
def home():
    posts=Posts.query.filter().order_by(Posts.date.desc()).all()
    last = math.ceil(len(posts)/int(params['no_of_posts']))
    page = request.args.get('page')
    if(not str(page).isnumeric()):
        page = 1
    page= int(page)
    posts = posts[(page-1)*int(params['no_of_posts']): (page-1)*int(params['no_of_posts'])+ int(params['no_of_posts'])]
    #Pagination Logic
    if (page==1):
        prev = "#"
        next = "/?page="+ str(page+1)
    elif(page==last):
        prev = "/?page=" + str(page - 1)
        next = "#"
    else:
        prev = "/?page=" + str(page - 1)
        next = "/?page=" + str(page + 1)
    return render_template('index.html', params=params, posts=posts, prev=prev, next=next)


@app.route("/about")
def about():
    return render_template('about.html',params=params)

#Registration form
@app.route("/register", methods=['GET', 'POST'])
def register():
    if(request.method=='POST'):
        '''Add entry to the database'''
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        useremail = Register.query.filter_by(email=email).first()
        username=Register.query.filter_by(name=name).first()
        userphone = Register.query.filter_by(phone_num=phone).first()

        if useremail:
            raise ValidationError("Email already exists")
            return render_template('register.html')
        elif userphone:
            raise ValidationError("Phone Number already exists")
            return render_template('register.html')
        entry = Register(email=email, phone_num=phone, name=name,
                             paas=generate_password_hash(password, method='sha256'))

        db.session.add(entry)
        db.session.commit()
        return render_template('login.html',params=params)
    return render_template('register.html',params=params)

#Login module
@app.route("/login", methods=['GET', 'POST'])
def login():
    posts = Posts.query.filter_by().all()
    if (request.method == 'POST'):
        email = request.form.get('email')
        password = request.form.get('password')
        user = Register.query.filter_by(email=email).first()
        # check if user actually exists
        # take the user supplied password, hash it, and compare it to the hashed password in database
        if not user or not check_password_hash(user.paas, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))  # if user doesn't exist or password is wrong, reload the page
        return redirect(url_for('admin', name=user.name))
    return render_template('login.html', params=params, posts=posts)

#Generating Access token
@app.route('/github')
def github_login():
    if not github.authorized:
        return redirect(url_for("github.login"))
    resp = github.get("/user")
    assert resp.ok
    return "You are @{login} on GitHub".format(login=resp.json()["login"])

#sending mail for password generation
def send_reset_email(user):
    token=user.get_token()
    msg=Message('Password reset Request',sender=params['gmail-user'],recipients=[user.email])
    msg.body=f'''To reset your password visit the following link:
{url_for('forgotpassword',token=token,_external=True)}
If you did not make this request do ignore the email.'''
    mail.send((msg))

#Password reset
@app.route('/forgot', methods=('GET', 'POST',))
def forgot():
    if current_user.is_authenticated:
        return render_template('admin.html')
    if (request.method == 'POST'):
         email = request.form.get('email')
         user = Register.query.filter_by(email=email).first()
         send_reset_email(user)
         flash('an email has been sent with instruction to reset password','info')
         return render_template('login.html')
    return render_template('ResetPassword.html')

#Password change function
@app.route('/forgot/<token>', methods=('GET', 'POST',))
def forgotpassword(token):
    if current_user.is_authenticated:
        return render_template('admin.html')
    user=Register.verify_token(token)
    if user is None:
        flash('that is an invalid or expired token','warning')
        return redirect(url_for('forgot'))
    if (request.method == 'POST'):
        password= request.form.get('password')
        #return render_template('login.html')
        hash_password = generate_password_hash(password, method='sha256')
        user.paas= hash_password
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('ResetPasswordSubmit.html',token=token)

#Admin page from where one can update & delete the posts
@app.route("/admin/<name>",methods=['GET', 'POST'])
def admin(name):
    user = Register.query.get(name)
    posts = Posts.query.filter_by().order_by(Posts.date.desc()).all()
    users = Register.query.all()
    for user3 in users:
        if current_user==user3:
           return user3
    return render_template('Admin.html', posts=posts, params=params,name=user,users=user3)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index.html',params=params))

#Adding new post
@app.route("/post", methods=['GET', 'POST'])
def post():
    if(request.method=='POST'):
        title = request.form.get('title')
        tag = request.form.get('tagLine')
        slug = request.form.get('slug')
        content = request.form.get('content')
        p1 = Posts(title=title, tagLine=tag,slug=slug,content=content)
        db.session.add(p1)
        db.session.commit()
        posts = Posts.query.all()
        user = Register.query.all()
        for user1 in user:
            if user1 == current_user:
                return user1
        return render_template('Admin.html', posts=posts,users=user1)
    return render_template('post.html')

#Reding the content of the post
@app.route('/<int:id>',methods=['POST','GET'])
def post_read(id=None):
    post = Posts.query.get(id)
    user=Register.query.all()
    for user1 in user:
        if user1==current_user:
            return user1
    return render_template('post_read.html',post=post,user=user1,params=params)

#Editing post
@app.route('/update/<int:id>', methods = ['GET', 'POST'])
def edit(id=None):
    post2 = Posts.query.filter_by(sno=id).first()
    if request.method == 'POST':
        post2.title=request.form.get('title')
        post2.tagLine=request.form.get('tagLine')
        post2.slug=request.form.get('slug')
        post2.content=request.form.get('content')
        db.session.commit()
        posts = Posts.query.all()
        user1 = Register.query.all()
        return render_template('Admin.html',posts=posts,users=user1)
    return render_template('edit.html', post=post2)

#updating account
@app.route('/account/<int:id>',methods = ['GET', 'POST'])
def account(id):
    user2 = Register.query.filter_by(sno=id).first()
    if request.method == 'POST':
        user2.name = request.form.get('name')
        user2.email = request.form.get('email')
        user2.phone_num = request.form.get('phone_num')
        db.session.commit()
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        user2.profile_image= filename
        db.session.commit()
        posts = Posts.query.all()
        user1 = Register.query.all()
        for user3 in user1:
            if current_user == user3:
                return user3
        return render_template('Admin.html', posts=posts, users=user3)
    return render_template('account.html', user=user2,profile_image=user2.profile_image)

#for getting file extension
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#Deleting post
@app.route('/delete/<int:id>', methods = ['GET', 'POST'])
def delete(id=None):
     post = Posts.query.filter_by(sno=id).first()
     db.session.delete(post)
     db.session.commit()
     posts = Posts.query.all()
     user1 = Register.query.all()
     for user3 in user1:
         if current_user == user3:
             return user3
     return render_template('Admin.html',posts=posts,users=user3)


if __name__=="__main__":
    app.run(debug=True)
