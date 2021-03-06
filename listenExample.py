from flask import render_template
from flask import Flask, url_for, redirect, request, send_from_directory
from werkzeug.utils import secure_filename
import os,json
import ron
from pymisp import PyMISP as pm
from pymisp import MISPEvent as me
from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis, MISPObject, MISPAttribute
from uuid import uuid4
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



UPLOAD_FOLDER = os.getcwd()+'/uploaded'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif','exe'])

app = Flask(__name__,static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 21 * 1024 * 1024 #16 MB max file size
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def checkboxes(att):
    checkb= [None,None]
    if "filesize" in att:
        checkb[0]="filesize"
    if "uint" in att:
        checkb[1]="uint"
    return checkb

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
        if 'file' not in request.files or len(request.files["file"].filename) == 0:
            return redirect(url_for("nofile"))
        else:
            file = request.files['file']
            attribs = checkboxes(request.form.getlist('atts'))
            vt_select = request.form.get("comp_select")

            size = sizes(request.form["size"])
            size_op = sizes(request.form["size_op"])
            many = sizes(request.form["many"])
            # if file and (allowed_file(file.filename) or "ELF" in z) :# <<<<<<<<<<<< TODO SE PERIPTOSH POU THELO NA PERIORISO TOYS TYPOYS ARXEION POU THA ANEVAZO
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            x = ron.create_new_yara(os.path.join(app.config['UPLOAD_FOLDER'], filename),attribs[0],attribs[1],vt_select,size,size_op,many)
            if x.result != False:
                file = open(x.yara_path,"r")
                rfile = file.read()
                file.close()
                all = x.ret_all_str()
                yara_name = x.yara_name
                all_op = x.ret_all_op()
                return render_template("hello2.html", x =rfile, all= all, all_op=all_op, filename = filename, vt=x.vt_results, sel=vt_select, yn=yara_name) #, print('kid' if age < 18 else 'adult')
            else:
                return redirect(url_for("noyara"))
    return render_template("hello.html")


@app.route('/uploaded_file/<filename><x>')
def uploaded_file(filename,x):
    return "heloo"+ filename,x


@app.route('/nofile/')
def nofile():
    return render_template("no_file.html")




#
# @app.route('/noyara/')
# def noyara():
#     return "Could not manage to generate YARA file"


@app.route('/noyara/')
def noyara():
    return render_template("no_yara.html")

@app.route('/misp/')
def misp():
    return "Unable to establish connection with MISP"

@app.route('/upload_to_MISP/')
def upload_to_MISP():
    return render_template("upload_to_misp.html", file=request.args.get('file', 1, type=str), yara=request.args.get('yara', 1, type=str))


@app.route('/yara_repository/')
def yara_repository():
    files = list()
    # r=root, d=directories, f = files
    for r, d, f in os.walk(os.getcwd() + "/yara_repository"):
        for file in f:
            files.append(file)
    return render_template("yararepo.html", all=files)


@app.route('/handle_data/', methods=['POST'])
def handle_data():
    yara = request.args.get('yaraa', 1, type=str)
    zip_file = request.args.get('filee', 1, type=str)#get(key, default=None, type=None)

    threat=[ThreatLevel.undefined,ThreatLevel.low,ThreatLevel.medium,ThreatLevel.high]
    analysis=[Analysis.initial,Analysis.ongoing,Analysis.completed]
    txt_event = request.form.get('misp_event')
    threat_sel = request.form.get('threat_select')
    analysis_html = request.form.get('anal_select')
    upl = bool(request.form.get('upl'))
    pub = bool(request.form.get('pub'))
    att_comm = request.form.get('att_com')

    #print(filename,typeof,analysis,upl,att_comm)

    try:

        misp = pm("https://192.168.1.10", "gQkJ6nqwWDZEakD9U5pUqZZDhuKpsz6X7kmB4e9b", False)
    except:
        return redirect(url_for("misp"))
    event = me()
    event.info = txt_event
    # second_event.distribution = "distribution org"
    #print(dir(second_event))
    if int(threat_sel) <0 or int(threat_sel)>3  or (isinstance(threat_sel, int) == False):
        threat_sel =0
    else:
        threat_sel = int(threat_sel)
        event.threat_level_id = threat[threat_sel]
    if int(analysis_html)<0 or int(analysis_html)>2 or (isinstance(threat_sel, int) == False):
        analysis_html = 0
    else:
        analysis_html =int(analysis_html)
        event.analysis = analysis[analysis_html]
    # second_event.set_date("Aug 18 2018")
    event.set_date(f"{datetime.today().month} {datetime.today().day} {datetime.today().year}")
    #event.add_attribute('text', str(uuid4()))
    # second_event.attributes[0].add_tag('tlp:white___test')
    #event.add_attribute('ip-dst', '1.1.1.1')
    #event.add_attribute('yara', '1.1.1.1')
    event.add_attribute('yara', yara)
    event.attributes[0].comment = att_comm
    # second_event.attributes[1].add_tag('tlp:amber___test')
    # Same value as in first event.
    # second_event.add_attribute('text', "hello")
    if pub == True:
        event.publish()
    try:
        x = misp.add_event(event)
        print("xxxx", x, dir(x))
        if upl == True:
            for root, dirs, files in os.walk(os.getcwd() + "/uploaded", topdown=False):
                if zip_file + ".zip" in files:
                    misp.add_attachment(x["Event"]["id"], os.getcwd()+"/uploaded/"+zip_file + ".zip")
        return redirect(url_for("upload_file"))
    except Exception as e:
        print(e)

@app.route('/badfiles/')
def badfiles():
    files = list()
    # r=root, d=directories, f = files
    for r, d, f in os.walk(os.getcwd() + "/uploaded"):
        for file in f:
            files.append(file)
    return render_template("badfilesrepo.html", all=files)


@app.route('/download/', methods=['GET', 'POST'])
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

