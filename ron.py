from __future__ import print_function
import os
import re
import yara
import json
import hashlib
import datetime
import random
import sys,math
import pefile
import zipfile
from elftools.elf.elffile import ELFFile
from pprint import pprint
from virus_total_apis import PublicApi as VirusTotalPublicApi
from capstone import *



ipv4 = '(?:\d{1,3}\.)+(?:\d{1,3})'  # OK
win_path = "[a-z][\:][\\|/][a-z]*[0-9]*[\\|/]*[a-z]*[0-9]*[\\|/]*[a-z]*[0-9]*"
site_path = "[w]{0,3}[\.]{0,1}.[^ ]*\.[a-z0-9]{2,6}[\\|/]*.[^ ]*[\\|/]*.[^ ]*[\\|/]*.[^ ]*[\\|/]*.[^ ]*[\\|/]*"
http_https = "(?:http|ftp)s?://.*"
base_64 = "(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)"
hex_blob = '([A-F]{10}|[0-9]{10})'
email = "[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2,12}|XN--[A-Z0-9]{4,18})"
pat_win32 = "WriteFile|IsDebuggerPresent|RegSetValue|CreateRemoteThread"
#pat_winsock = b"WS2_32.dll|WSASocket|WSASend|WSARecv|Microsoft Visual C++"
pat_regkeys = "HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|CurrentVersion.Run|CurrentVersion.RunOnce|UserInit"
#filenames = b"\\drivers\\etc\\hosts|cmd\\.exe|\\Start Menu\\Programs\\Startup"
intresting_strs = "password|login|pwd|administrator|admin|root|smtp|pop|ftp|ssh|icq|backdoor|vmware"
regexes = {"ipv4": ipv4,"win_path" : win_path,"site_path": site_path, "http_https":http_https,"base_64": base_64,"hex_blob":hex_blob,"email":email,"pat_win32":pat_win32,"pat_regkeys":pat_regkeys,"intresting_strs":intresting_strs}

API_KEY = 'ddf8f1441192dca57af482e1c916421e974a955bff35fdcd4553ceed507fc453'
def magic_bytes():
    with open("magic_bytes.json", "r") as file:
        x = json.load(file)
        return x

class new_YARA():
    def __init__(self,path,filesize,uint,vt,up_vt,size,size_op,many):
        self.path = path
        self.md5 = None
        self.sha256=None
        self.file_type = None
        self.yara_path = None
        self.yara_name = None
        self.result = False
        self.filebytes = None
        self.vt_results = None
        self.size = size
        self.size_op = size_op
        self.many = many
        self.filesize = filesize
        self.uint = uint
        self.vt = vt
        self.up_vt = up_vt
        self.printable_strings=list()
        self.opcodes = list()
        self.rules = list()
        counter =0
        while self.result == False and counter <3:

            self.create_yara()
            self.check_yara()
            counter+=1
            if self.result == True:
                self.zipeverything()

    # def extruct_url(self,chunk):
    #     url = re.match(regex, chunk)
    #     if url:
    #         self.rules.append(url)
    def get_hashes(self):
        self.md5 = hashlib.md5(open(self.path, 'rb').read()).hexdigest()
        self.sha256 = hashlib.sha256(open(self.path, 'rb').read()).hexdigest()
        if (self.vt == "md5" and self.up_vt == None) or (self.vt == "md5" and self.up_vt == "up"):
            try:
                vt = VirusTotalPublicApi(API_KEY)
                #self.md5 = "4b26e810448141b3238895373c87f55a"
                response = vt.get_file_report(self.md5)
                x = json.dumps(response, sort_keys=False, indent=4)
                self.vt_results = json.loads(x)
            except Exception as e:
                self.vt_results = "error while attempting to connect to Virus Total Status ", e
        if self.vt == None and self.up_vt == "up":
            try:
                vt = VirusTotalPublicApi(API_KEY)
                response = vt.scan_file("app.exe")
                report = vt.get_file_report(response["results"]["md5"])
                print("Upload")
            except Exception as err:
                print(err)

    def mb(self,mb):
        if len(mb) >= 8:
            x = mb[0:8]
            of = "32"
            res = "".join(map(str.__add__, mb[-2::-2], mb[-1::-2]))
        elif len(mb) >= 4 and len(mb) < 8:
            x = mb[0:4]
            of = "16"
            res = "".join(map(str.__add__, mb[-2::-2], mb[-1::-2]))
        elif len(mb) >= 2 and len(mb) < 4:
            x = mb[0:2]
            of = "8"
            res = "".join(map(str.__add__, mb[-2::-2], mb[-1::-2]))
        else:
            of = ""
            res = ""
        return of, res


    def regex_returns(self, allstrings):
        from_regex = {}
        temp_list = []
        for key, value in regexes.items():
            from_regex[key] = []
        for key, value in regexes.items():
            for j in allstrings:
                x = re.findall(value, j.decode("utf-8"))
                if len(x) != 0:
                    temp_list.append(x[0])
            if len(temp_list) != 0:
                for i in temp_list:
                    from_regex[key].append(i)
            temp_list.clear()
        return from_regex

    def extract_opcodes(self,fileData):
        # String list
        # Read file data
        try:
            pe = pefile.PE(data=fileData)
            name = ""
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            pos = 0
            for sec in pe.sections:
                if (ep >= sec.VirtualAddress) and \
                        (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
                    name = sec.Name.replace(b'\x00', b'')
                    break
                else:
                    pos += 1
            for section in pe.sections:
                if section.Name.rstrip("\x00".encode()) == name:
                    text = section.get_data()
                    # Split text into subs
                    text_parts = re.split("[\x00]{3,}".encode(), text)
                    for text_part in text_parts:
                        if text_part == '' or len(text_part) < 8:
                            continue
                        self.opcodes.append(text_part[:16].hex())

        except Exception as e:
            print(e)
            pass
    def extract_elf_opcodes(self, data):
        elf = ELFFile(data)
        code = elf.get_section_by_name('.text')
        ops = code.data()
        addr = code['sh_addr']
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        # count = 0
        for i in md.disasm(ops, addr):
            # print(dir(i))
            if len(i.bytes.hex()) > 16:
                self.opcodes.append(i.bytes.hex())

    def getStrings(self):
        try:
            with open(self.path, 'rb') as f:
                data = f.read()
                chars = r"A-Za-z0-9/\-:.,_$%@'()\\\{\};\]\[<> "
                regexp = r'[%s]{%d,100}' % (chars, 6)
                regexp = regexp.encode()
                pattern = re.compile(regexp)
                strlist = pattern.findall(data)
                # Get Wide Strings
                unicode_str = re.compile(b'(?:[\x20-\x7E][\x00]){6,100}')  # ,re.UNICODE )
                unicodelist = unicode_str.findall(data)
                allstrings = unicodelist + strlist
                # Extract Strings of Interest
                from_regex = self.regex_returns(allstrings)
                if self.size_op > 0:
                    if data[0:2] == b"MZ":
                        self.extract_opcodes(data)
                    elif data[1:4] == b"ELF":
                        self.extract_elf_opcodes(f)
                if len(allstrings) > 0:
                    self.printable_strings = list(set(allstrings))
                    return list(set(allstrings)), from_regex, list(set(self.opcodes))
                else:
                    # print ('[!] No Extractable Attributes Present in Hash: '+str(.md5sum(filename)) + ' Please Remove it from the Sample Set and Try Again!')
                    print("EXCEPTION1")
                    sys.exit(1)
        except Exception as w:
            print("EXCEPTION2", w)
            # print ('[!] No Extractable Attributes Present in Hash: '+str(md5sum(filename)) + ' Please Remove it from the Sample Set and Try Again!')
            sys.exit(1)

    def check_yara(self):
        try:
            x = yara.compile(self.yara_path)
            f_check = x.match(self.path)
            if f_check:
                self.result = True
            else:
                self.result = False
        except Exception as err:
            self.result = False
            print(err)

    def get_file_type(self):
        types_from_magic = list()
        f_sings = list()
        with open(self.path, "rb") as f:
            file_bytes = f.read().hex()
            mb = magic_bytes()
            for i in mb:
                signs = mb[i]['signs']
                for sign in signs:
                    a = sign.split(",")
                    byte_to_check = file_bytes[int(a[0]):int(len(a[1]))]
                    if byte_to_check.lower() == a[1].lower():
                        types_from_magic.append(i)
                        f_sings.append(sign)
        file_type = types_from_magic
        f.close()
        return file_type, f_sings

    def calc_size(self):
        self.size = int(self.size)
        if self.size == 0 and self.size_op == 0:
            self.size = 15
        elif self.size == 0 and self.size_op > 0:
            self.size = 0

        if len(self.printable_strings)<self.size:
            self.size = len(self.printable_strings)
    def calc_many(self):
        if self.size+self.size_op<self.many:
            hm = "all"
        else:
            hm = str(self.many+self.size_op)
        if self.many == 0 or self.many == "":
            hm = "all"
        return hm


    def calc_filesize(self):
        self.filebytes = math.floor(int(os.path.getsize(self.path)))
        if self.filebytes <= 3072:
            f_size = f"and (filesize > {0}KB and filesize < 4KB)"
        else:
            self.filebytes = self.filebytes/1024
            f_size = f"and (filesize > {math.floor(self.filebytes-2)}KB and filesize < {round(self.filebytes+2)}KB)"
        return f_size

    def create_yara(self):
        self.get_hashes()
        self.getStrings()

        self.calc_size()
        randOpcodes=""
        hmany = self.calc_many()
        randStrings = random.sample(self.printable_strings,self.size)

        if len(self.opcodes)>0:
            randOpcodes=random.sample(self.opcodes,self.size_op)
        self.yara_name = os.path.basename(self.path).split(".")[0]
        #x = "abcd><!@#$^&*()(*&^ %$#@\\"
        z = " !@#$%^&*()-+{}\",.<>?/;'\\[]:"
        for i in z:
            self.yara_name = self.yara_name.replace(i, "")
        self.yara_name = "Yara_"+self.yara_name
        self.yara_path = os.getcwd()+"/yara_repository/"+self.yara_name+".yara"
        ruleOutFile = open(self.yara_path, "w")
        ruleOutFile.write("rule " + self.yara_name)
        ruleOutFile.write("\n")
        ruleOutFile.write("{\n")
        ruleOutFile.write("meta:\n")
        ruleOutFile.write("\tdate = \"" + str(datetime.datetime.now().date()) + "\"\n")
        ruleOutFile.write("\thash_md5 = \"" + self.md5 + "\"\n")
        ruleOutFile.write("\thash_sha256 = \"" + self.sha256 + "\"\n")
        file_type, offset_byte = self.get_file_type()
        ruleOutFile.write("\tsample_filetype = \"" + ' '.join(file_type) + "\"\n")
        ruleOutFile.write("strings:\n")
       # print(randStrings)
        c = 0
        for s in randStrings:
            s = s.decode("utf-8")
            if "\x00" in s:
                ruleOutFile.write(
                    "\t$string" + str(c) + " = \"" + s.replace("\\", "\\\\").replace('"', '\\"').replace(
                        "\x00", "") + "\" wide\n")
            else:
                ruleOutFile.write("\t$string" + str(c)+ " = \"" + s.replace("\\", "\\\\") + "\"\n")
            c += 1
        if len(randOpcodes)>0:
            c=0
            for s in randOpcodes:
                ruleOutFile.write("\t$opcode"+ str(c)+" = {"+s+"} \n")
                c+=1
        ruleOutFile.write("condition:\n")
        f_unit=""
        if self.uint == "uint":
            if len(offset_byte)!=0:
                a = offset_byte[0].split(",")
                uint, res = self.mb(a[1])
                if len(uint)!=0:
                    f_unit = f"and uint{uint}({a[0]}) == 0x{res}"
        else:
            f_unit=""
        if self.filesize == "filesize":
            f_size = self.calc_filesize()
        else:
            f_size=""
        ruleOutFile.write(f"\t {hmany} of them {f_unit} {f_size} \n")
        ruleOutFile.write("}\n")
        ruleOutFile.close()
        return


    def zipeverything(self):
        zip = os.getcwd()+f"\\uploaded\\{self.yara_name}.zip"
        basen = os.path.basename(self.path)
        my_zip = zipfile.ZipFile(zip, "w", zipfile.ZIP_DEFLATED)
        my_zip.write(self.path, basen)
        #file = os.getcwd()+f"\\yara_repository\\{self.yara_path}"
        basen = os.path.basename(self.yara_path)
        #print(self.yara_path, basen)
        my_zip.write(self.yara_path, basen)
        my_zip.close()
        os.remove(self.path)
        del zip,basen,my_zip


    def ret_all_str(self):
        strings_from_bytes = list()
        for i in self.printable_strings:
            strings_from_bytes.append(i.decode("utf-8"))
        return strings_from_bytes
    def ret_all_op(self):
        if len(self.opcodes)>0:
            return set(self.opcodes)
        else:
            return "No Opcodes"





def create_new_yara(path,filesize,uint,vt,up_vt,size,size_op,many):
    ny = new_YARA(path,filesize,uint,vt,up_vt,size,size_op,many)
    return ny


