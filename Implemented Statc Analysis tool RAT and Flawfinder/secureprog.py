import bcrypt
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for, send_file,session,flash
from werkzeug import secure_filename
from flask.ext.pymongo import PyMongo
from datetime import timedelta
import re
import magic



app = Flask(__name__)
tempfile=""
app.config.from_pyfile('config.cfg')
app.config['MONGO_DBNAME']
app.config['MONGO_URI']
mongo = PyMongo(app)
secret_key = os.urandom(24)
# session.permanent = True
# app.permanent_session_lifetime = timedelta(seconds=10)
# This is the path to the upload directory
app.config['UPLOAD_FOLDER'] = 'uploads/'
# These are the extension that we are accepting to be uploaded
app.config['ALLOWED_EXTENSIONS'] = set(['java', 'py', 'c','pl','php'])
app.config['ALLOWED_DATA']=set(['C source','Python script','Perl script','PHP script'])
# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

@app.before_request
def make_session_permanent():
    # session will remain valid even if the browser is closed
    session.permanent = True
    # session will remain valid till 10 minutes
    app.permanent_session_lifetime = timedelta(minutes=10)
    # app.permanent_session_lifetime = timedelta(seconds=10)

@app.route('/')
def index():
    if 'username' in session:
        return  render_template('upload.html')

    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name': request.form['username']})

    if login_user:
        if bcrypt.hashpw(request.form['pass'].encode('utf-8'), login_user['password'].encode('utf-8')) == login_user[
            'password'].encode('utf-8'):
            session['username'] = request.form['username']

            session['user_id'] = str(login_user['_id'])

            return redirect(url_for('index'))

    flash('Invalid username/password combination')
    return redirect(url_for('index'),code=302)
	
	
@app.route('/upload', methods=['POST'])
def upload():
    # Get the name of the uploaded file
    file = request.files['file']
    # Check if the file is one of the allowed types/extensions
    if file and allowed_file(file.filename):
        global tempfile
        tempfile=magic.from_buffer(file.read(1024))

        llist=tempfile.split(",")
        
        llist[0]=llist[0].strip()
        
        if llist[0] in app.config['ALLOWED_DATA']:
            # Make the filename safe, remove unsupported chars
            filename = secure_filename(file.filename)
            # Move the file form the temporal folder to
            # the upload folder we setup
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # Redirect the user to the uploaded_file route, which
            # will basicaly show on the browser the uploaded file
            return redirect(url_for('uploaded_file',
                                filename=filename))

    flash("Please upload valid file")
    return redirect(url_for('index'),code=302)
# This route is expecting a parameter containing the name
# of a file. Then it will locate that file on the upload
# directory and show it on the browser, so if the user uploads
# an image, that image is going to be show after the upload
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    llist = tempfile.split(",")
    llist[0] = llist[0].strip()

    SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__));
    userfilepath = os.path.join(SCRIPT_PATH, "uploads", filename)
    inputfilename=filename
    if llist[0] == 'C source':
        resultflawfile=filename+"_flawoutput.txt"
        outputfile = os.path.join(SCRIPT_PATH, "uploads", filename+"_flawoutput.txt");
        resultratfile=filename+"_ratoutput.txt"
        rats_output_filename= os.path.join(SCRIPT_PATH, "uploads",  filename+"_ratoutput.txt");
        rats_system_query = "rats -w 3 " + filename + " > " + rats_output_filename
        subprocess.Popen(rats_system_query, shell=True)
        flawfinder_system_query = "flawfinder " + userfilepath + " > " + outputfile
        subprocess.Popen(flawfinder_system_query, shell=True)
    elif llist[0] == 'Python script'or llist[0] == 'Perl script' or llist[0]=='PHP script':
        resultflawfile = filename + "_flawoutput.txt"

        resultratfile = filename + "_ratoutput.txt"
        rats_output_filename = os.path.join(SCRIPT_PATH, "uploads",resultratfile);
        rats_system_query = "rats -w 3 " + filename + " > " + rats_output_filename
        subprocess.Popen(rats_system_query, shell=True)
    users_output = mongo.db.users_output
    #loggedin_user = users.find_one({'name': session['username']})

    fileflawread=""
    fileratread=""

    user_id = session['user_id']
    test = {'uid':user_id,'filetype':llist[0],'fileflawcontent': fileflawread, 'fileratcontent':fileratread,'filename': inputfilename, 'resultflawfile': resultflawfile,'resultratfile':resultratfile}
    users_output.insert(test)
    return render_template('outputfile.html')
@app.route('/outputfile', methods=['GET'])
def outputfile():
    users_output = mongo.db.users_output
    login_user_output = users_output.find({'uid': session['user_id']})

    if login_user_output:
        filename = list()
        fileflawcontentt=list()
        fileratcontentt=list()
        flawflag=0
        ratsflag=0
        for test in login_user_output:
            fileflaw_content = test['fileflawcontent']
            fileflaw_name=test['resultflawfile']
            filerat_content = test['fileratcontent']
            filerat_name = test['resultratfile']
            filetype=test['filetype']
            if fileflaw_content=="" or filerat_content=="":
                # read from file and update
                SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__));
                outputflawfile = os.path.join(SCRIPT_PATH, "uploads",fileflaw_name);
                outputratfile=os.path.join(SCRIPT_PATH, "uploads",filerat_name);
                if os.path.exists(outputflawfile) :
                    fileflaw_object = open(outputflawfile,'r')
                    fileflaw_content=fileflaw_object.read()
                    os.remove(outputflawfile)
                    flawflag=1
                if os.path.exists(outputratfile):
                    filerat_object = open(outputratfile, 'r')
                    filerat_content = filerat_object.read()
                    os.remove(outputratfile)
                    ratsflag=1
                    
                if flawflag == 0:
                    fileflaw_content='Not Applicable'
                if ratsflag==0:
                    filerat_content='Not Applicable'
                user_id_filter =  {'uid':str(session['user_id'])}
                data_update = {'fileflawcontent':fileflaw_content,'fileratcontent':filerat_content}
                set_filter = {'$set': data_update}

                users_output.update(user_id_filter, set_filter)

                filename.append(test['filename'])
                fileflawcontentt.append(fileflaw_content)
                fileratcontentt.append(filerat_content)
            else:
                filename.append(test['filename'])
                fileflawcontentt.append(fileflaw_content)
                fileratcontentt.append(filerat_content)
                return render_template('outputfile.html', filename=filename, fileflawcontentt=fileflawcontentt,
                                       fileratcontentt=fileratcontentt)
        return render_template('outputfile.html', filename=filename, fileflawcontentt=fileflawcontentt,fileratcontentt=fileratcontentt)

def is_username_valid(username):
    """Validate the email address using a regex."""
    if not re.match("^[a-zA-Z0-9]+$", username):
        return False
    return True
def is_password_valid(password):
    """Validate the email address using a regex."""
    if not re.match("^[a-zA-Z0-9]+$", password):
        return False
    return True


@app.route('/register', methods=['POST', 'GET'])
def register():
   
    if request.method == 'POST':
        username= request.form['username'].strip()
        password=request.form['pass'].strip()
        if not username or not password:
            
            flash("Please enter all the fields.")
            return redirect(url_for('register'),code=302)

        elif not is_username_valid(username):
                flash("Please enter a valid username and password")
                return redirect(url_for('register'))
        elif not is_password_valid(password):
               flash("Please enter a valid username and password")
               return redirect(url_for('register'))
        else:
            users = mongo.db.users
            existing_user = users.find_one({'name':username})

            if existing_user is None:
                hashpass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                user_detail = users.insert({'name': username, 'password': hashpass})


                return redirect(url_for('index'))

            return 'That username already exists!'
   
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
def logout():
   # remove the username from the session if it is there
   session.pop('username', None)
   session.pop('user_id',None)
   return redirect(url_for('index'))

if __name__ == '__main__':
    app.secret_key = secret_key
    app.run("") #Enter your EC2 URL