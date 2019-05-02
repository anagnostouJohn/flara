from flask import render_template
from flask import Flask, url_for, redirect, request, send_from_directory
from werkzeug.utils import secure_filename
import os,json
import ron



UPLOAD_FOLDER = os.getcwd()+'/uploaded'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif','exe'])

app = Flask(__name__,static_folder='yara_repository')
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
            # if file and (allowed_file(file.filename) or "ELF" in z) :# <<<<<<<<<<<< TODO SE PERIPTOSH POU THELO NA PERIORISO TOYS TYPOYS ARXEION POU THA ANEVAZO
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
            # else:
            #     return redirect(url_for("no proper file"))
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


@app.route('/yara_repository/')
def yara_repository():
    files = list()
    # r=root, d=directories, f = files
    for r, d, f in os.walk(os.getcwd() + "/yara_repository"):
        for file in f:
            files.append(file)
    return render_template("yararepo.html", all=files)


@app.route('/badfiles/')
def badfiles():
    files = list()
    # r=root, d=directories, f = files
    for r, d, f in os.walk(os.getcwd() + "/uploaded"):
        for file in f:
            files.append(file)
    return render_template("badfilesrepo.html", all=files)


# @app.route('/download/<path:filename>', methods=['GET', 'POST'])
@app.route('/download/', methods=['GET', 'POST'])
#def download(filename):
def download():
    filename = request.args.get('filename', 1, type=str)
    typeof = request.args.get('typeof', 1, type=str)

    if typeof == "bad":
        uploads = os.getcwd() + "/uploaded/"
    elif typeof == "yara":
        uploads = os.getcwd()+"/yara_repository/"
    return send_from_directory(directory=uploads, filename=filename)






if __name__ == "__main__":
    yara_f_path = os.getcwd()+"/yara_repository"
    upload_f_path = os.getcwd() + "/uploaded"
    if not os.path.exists(yara_f_path):
        os.makedirs(yara_f_path)
    if not os.path.exists(upload_f_path):
        os.makedirs(upload_f_path)
    del yara_f_path,upload_f_path
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


