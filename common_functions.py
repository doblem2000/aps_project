from subprocess import run, Popen, PIPE
import pickle
import csv
import base64
import datetime
import math
import json

def generate_context(numero_di_player):
  for i in range(numero_di_player):
    shell("mkdir player{0}".format(i))
    # print("- Generating dsaparams:\n")
    # shell("openssl dsaparam -out common/dsaparam{0}.pem 1024".format(str(i)))
    # shell("openssl dsaparam -in common/dsaparam{0}.pem -text".format(str(i)))
    print("\n- Generating DSA private and public keys:\n")
    shell("openssl gendsa -out player{0}/dsa_key.pem common/dsaparam.pem".format(str(i)))
    shell("openssl dsa -in player{0}/dsa_key.pem -pubout -out common/player{1}_dsa_key.pem".format(str(i),str(i)))
    
### Base64 functions
def encode_bytes_to_base64(b):
  return base64.encodebytes(b).decode()

def decode_base64_to_bytes(s):
  return base64.decodebytes(s.encode())

def list_encode_bytes_to_base64(list):
  l=[]
  for i in range(len(list)):
    l.append(encode_bytes_to_base64(list[i]))
  return l

def list_decode_base64_to_bytes(list):
  l=[]
  for i in range(len(list)):
    l.append(decode_base64_to_bytes(list[i]))
  return l

### SHELL functions

# Execute a shell script and returns stdout
def shell(cmd, args = {}):
  res = run(cmd,*args,shell=True, capture_output=True)
  return res.stdout 

### PRG functions

# Generates n pseudorandom bits using a prg. n must be a multiple of 8. output is type 'int'
def prg(n):
  random_bytes = shell("openssl rand {0}".format(int(n/8)))
  return int.from_bytes(random_bytes, byteorder='big')

### DSA key management functions

# Helper function to extract fields of a DSA key file
def extract_dsa_between(bytes, start, end = None):
  s = bytes.decode("utf-8")
  s = s.split(start)[1]
  if end is not None: s = s.split(end)[0] #extract private key
  s = "".join(s.split()) #Clear whitespaces
  s = s.replace(":", "") #Remove commas 
  ret = int(s, base=16) #Convert to int
  return ret

# Extracts the secret key from a DSA key file
def extract_dsa_secret(path):
  bytes = shell("openssl dsa -in {0} -text -noout".format(path))
  x = extract_dsa_between(bytes,'priv:','pub:')
  y = extract_dsa_between(bytes,'pub:','P:')
  p = extract_dsa_between(bytes,'P:','Q:')
  q = extract_dsa_between(bytes,'Q:','G:')
  g = extract_dsa_between(bytes,'G:')
  return (x,y,p,q,g)

# Extracts the public key from a DSA public key file
def extract_dsa_public(path):
  bytes = shell("openssl dsa -pubin -in {0} -text -noout".format(path))
  y = extract_dsa_between(bytes,'pub:','P:')
  p = extract_dsa_between(bytes,'P:','Q:')
  q = extract_dsa_between(bytes,'Q:','G:')
  g = extract_dsa_between(bytes,'G:')
  return (y,p,q,g)

# Extracts the public key from a x509 certificate
def extract_public_from_cert(path):
  return shell("openssl x509 -pubkey -noout < {0}".format(path))

### ECDSA functions

#nome = attore che possiede chiave privata nella sua directory 
def load_ecdsa_secret(name):
  SK= shell("cat {0}/ecdsa_key.pem".format(name)).decode("utf-8")
  return SK

#name= indica nome chiave all'interno della directory common
def load_ecdsa_public(name):
  PK= shell("cat common/{0}.pem".format(name)).decode("utf-8")
  return PK

#This function is used to sign a message m with ECDSA+SHA256 with the secret key SK
def hash_and_sign(SK,m):
    shell("echo \"{0}\" > temp.pem".format(SK))
    shell("echo \"{0}\" > tempm.txt".format(m))
    signature=shell("openssl dgst -sha256 -sign temp.pem tempm.txt")
    shell("rm temp.pem")
    shell("rm tempm.txt")
    return signature #signature is a byte string
  
#This function is used to verify a signature sigma on a message m with ECDSA+SHA256 with the public key PK
def vrfy(PK,m,sigma):
    shell("echo \"{0}\" > tempPK.pem".format(PK))
    shell("echo \"{0}\" > tempm.pem".format(m))
    
    #creare file binario
    with open("tempsigma.pem","wb") as fp:
      fp.write(sigma)
    stdout = shell("openssl dgst -sha256 -verify tempPK.pem -signature tempsigma.pem tempm.pem").decode("utf-8")
    shell("rm tempPK.pem")
    shell("rm tempm.pem")
    shell("rm tempsigma.pem")
    if stdout.__contains__("OK"):
      return True
    else:
      print(stdout)
      return False

### SHA256 functions

def sha256(m): #SHA256 hash function
    cs=shell("echo \"{0}\" | openssl dgst -sha256".format(m)).decode("utf-8")
    c=cs.split(" ")[1]
    return c.strip()  


### TLS functions
def server_open_tls():
  server = Popen("openssl s_server -port 8444 -key temp/wwwkey.pem -cert temp/wwwcert.pem -CAfile temp/cacert.pem -quiet -verify_quiet", shell=True, stdout=PIPE, stdin=PIPE, stderr=PIPE)
  return server

def kill_tls():
  shell("killall -s SIGKILL openssl")

def server_read_obj(server):
  return pickle.load(server.stdout)

def client_send_obj(obj):
  dump = pickle.dumps(obj)
  client = Popen("openssl s_client -connect localhost:8444 -CAfile temp/cacert.pem -servername server -quiet -verify_quiet -no_ign_eof", shell=True,stdin=PIPE)
  client.communicate(input=dump)