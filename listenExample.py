from flask import render_template
from flask import Flask, url_for, redirect, request, flash
from werkzeug.utils import secure_filename
import os,json
import ron
app = Flask(__name__)

class penis():
    def __init__(self, my_penis):
        self.penis=my_penis
        self.size = 10
    def calculate_size(self):
        self.size+=10
        return self.size

UPLOAD_FOLDER = r'C:\Users\john\Desktop\workSpace\yara_cr\uploaded'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif','exe'])

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 21 * 1024 * 1024 #16 MB max file size
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def checkboxes(att):
    if "filesize" in att and "uint" not in att:
        att.append(None)
    elif "filesize" not in att and "uint" in att:
        att.insert(0,None)
    elif "filesize" not in att and "uint" not in att:
        att.append(None)
        att.append(None)
    else:
        pass
    return att
def sizes(size):

    if size == "":
        size = 0
    size = int(size)
    if size < 0:
        size = 0
    return size


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(url_for("nofile"))
        else:
            file = request.files['file']
            attribs = checkboxes(request.form.getlist('atts'))
            size = sizes(request.form["size"])
            size_op = sizes(request.form["size_op"])
            many = sizes(request.form["many"])
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                x = ron.create_new_yara(os.path.join(app.config['UPLOAD_FOLDER'], filename),attribs[0],attribs[1],size,size_op,many)
                if x.result != False:
                    file = open(x.yara_path,"r")
                    rfile = file.read()
                    file.close()
                    all = x.ret_all_str()
                    all_op = x.ret_all_op()
                    return render_template("hello2.html", x =rfile, all= all, all_op=all_op, filename = filename)#, data=map(json.dumps, L))
                else:
                    return redirect(url_for("noyara"))
    return render_template("hello.html")


@app.route('/uploaded_file/<filename><x>')
def uploaded_file(filename,x):
    return "heloo"+ filename,x


@app.route('/nofile/')
def nofile():
    return "No File Selected"

@app.route('/noyara/')
def noyara():
    return "Could not manage to generate YARA file"


@app.route('/page/')
def page():
    return "on page"


@app.errorhandler(413)
def error413(e):
    print("EDO",e )
    return "PENIS",413


if __name__ == "__main__":
    #app.run(host='0.0.0.0',debug=True)
    app.run(debug=True)

#
#
#
#
# import os
# from flask import Flask, flash, request, redirect, url_for
# from werkzeug.utils import secure_filename
#




#
#     return '''
#     <!doctype html>
#     <title>Upload new Filebiloguouhio</title>
#     <h1>Upload new File</h1>
#     <form method=post enctype=multipart/form-data>
#       <input type=file name=file>
#       <input type=submit value=Upload>
#     </form>
#     '''
# @app.route('/uploaded_file/<filename>/<x>')
# def uploaded_file(filename,x):
#     return "heloo"+ filename+ "_____",x


# # @app.route('/hello/')
# @app.route('/hello/<names>')
# def projects(names=None):
#     return render_template('hello.html', name=names)
#     #return redirect("http://www.google.com", code=302)
#     #return 'The project page'
#
# @app.route('/about')
# def about():
#     return 'The about page'


#
# @app.route('/user/<username>')
# def show_user_profile(username):
#     # show the user profile for that user
#     x = hello(username)
#     return f'User {x.printme()}'
#     #x = hello(username)
#     #return x
#
#
# @app.route('/post/<int:post_id>')
# def show_post(post_id):
#     # show the post with the given id, the id is an integer
#     return 'Post %d' % post_id
#
# @app.route('/path/<path:subpath>')
# def show_subpath(subpath):
#     # show the subpath after /path/
#     return 'Subpath %s' % subpath
#
#
#
# class hello():
#     def __init__(self, name):
#         self.name=name
#     def printme(self):
#         self.name = self.name + "12345"
#         return self.name


