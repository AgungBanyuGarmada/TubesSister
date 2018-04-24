import string
import os
import time
import pickle
import socket
import threading

def bruteForce():
    ALPHA_LOWER = (string.ascii_lowercase,)
    ALPHA_UPPER = (string.ascii_uppercase,)
    ALPHA_MIXED = (string.ascii_lowercase, string.ascii_uppercase)
    PUNCTUATION = (string.punctuation,)
    NUMERIC = (''.join(map(str, range(0, 10))),)
    ALPHA_LOWER_NUMERIC = (string.ascii_lowercase, ''.join(map(str, range(0, 10))))
    ALPHA_UPPER_NUMERIC = (string.ascii_uppercase, ''.join(map(str, range(0, 10))))
    ALPHA_MIXED_NUMERIC = (string.ascii_lowercase, string.ascii_uppercase, ''.join(map(str, range(0, 10))))
    ALPHA_LOWER_PUNCTUATION = (string.ascii_lowercase, string.punctuation)
    ALPHA_UPPER_PUNCTUATION = (string.ascii_uppercase, string.punctuation)
    ALPHA_MIXED_PUNCTUATION = (string.ascii_lowercase, string.ascii_uppercase, string.punctuation)
    NUMERIC_PUNCTUATION = (''.join(map(str, range(0, 10))), string.punctuation)
    ALPHA_LOWER_NUMERIC_PUNCTUATION = (string.ascii_lowercase, ''.join(map(str, range(0, 10))), string.punctuation)
    ALPHA_UPPER_NUMERIC_PUNCTUATION = (string.ascii_uppercase, ''.join(map(str, range(0, 10))), string.punctuation)
    ALPHA_MIXED_NUMERIC_PUNCTUATION = (
        string.ascii_lowercase, string.ascii_uppercase, ''.join(map(str, range(0, 10))), string.punctuation
    )

    character_sets = {
        "01": ALPHA_LOWER,
        "02": ALPHA_UPPER,
        "03": ALPHA_MIXED,
        "04": NUMERIC,
        "05": ALPHA_LOWER_NUMERIC,
        "06": ALPHA_UPPER_NUMERIC,
        "07": ALPHA_MIXED_NUMERIC,
        "08": PUNCTUATION,
        "09": ALPHA_LOWER_PUNCTUATION,
        "10": ALPHA_UPPER_PUNCTUATION,
        "11": ALPHA_MIXED_PUNCTUATION,
        "12": NUMERIC_PUNCTUATION,
        "13": ALPHA_LOWER_NUMERIC_PUNCTUATION,
        "14": ALPHA_UPPER_NUMERIC_PUNCTUATION,
        "15": ALPHA_MIXED_NUMERIC_PUNCTUATION
    }

    hashes = {
        "01": "MD5",
        "02": "MD4",
        "03": "LM",
        "04": "NTLM",
        "05": "SHA1",
        "06": "SHA224",
        "07": "SHA256",
        "08": "SHA384",
        "09": "SHA512"
    }

    prompt = "Specify the character set to use:{}{}".format(os.linesep, os.linesep)
    for key, value in sorted(character_sets.items()):
        prompt += "{}. {}{}".format(key, ''.join(value), os.linesep)

    while True:
        try:
            charset = raw_input(prompt).zfill(2)
            selected_charset = character_sets[charset]
        except KeyError:
            print("{}Please select a valid character set{}".format(os.linesep, os.linesep))
            continue
        else:
            break

    prompt = "{}Specify the maximum possible length of the password: ".format(os.linesep)

    while True:
        try:
            password_length = int(raw_input(prompt))
        except ValueError:
            print("{}Password length must be an integer".format(os.linesep))
            continue
        else:
            break

    prompt = "{}Specify the hash's type:{}".format(os.linesep, os.linesep)
    for key, value in sorted(hashes.items()):
        prompt += "{}. {}{}".format(key, value, os.linesep)

    while True:
        try:
            hash_type = hashes[raw_input(prompt).zfill(2)]
        except KeyError:
            print("{}Please select a supported hash type".format(os.linesep))
            continue
        else:
            break

    prompt = "{}Specify the hash to be attacked: ".format(os.linesep)

    while True:
        try:
            user_hash = raw_input(prompt)
        except ValueError:
            print("{}Something is wrong with the format of the hash. Please enter a valid hash".format(os.linesep))
            continue
        else:
            break

    print("{}Cracking...{}".format(os.linesep, os.linesep))  # , flush=True)

    s = connection('localhost', 5005)
    start_time = time.time()

    min_pass_length = 1

    packet = pickle.dumps(
        [hash_type.lower(), user_hash.lower(), ''.join(selected_charset), min_pass_length, password_length])
    s.send(packet)

    threading._start_new_thread(getMessage, (s,))

    while True:
        if counter >= 4:
            print "can not find a match password"
            break
        if status != "NOT FOUND":
            print "Password FOUND : " + status
            break
    print("Took {} seconds".format(time.time() - start_time))

def connection(ip,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip,port))
    return s

def getMessage(s):
    global counter
    global status
    while True:
        message=s.recv(1024)
        if message == "NOT FOUND":
            counter=counter+1
        else:
            status=message
            break

def dictionary_attack():
    hashes = {
        "01": "MD5",
        "02": "MD4",
        "03": "LM",
        "04": "NTLM",
        "05": "SHA1",
        "06": "SHA224",
        "07": "SHA256",
        "08": "SHA384",
        "09": "SHA512"
    }

    prompt = "{}Specify the hash's type:{}".format(os.linesep, os.linesep)
    for key, value in sorted(hashes.items()):
        prompt += "{}. {}{}".format(key, value, os.linesep)

    while True:
        try:
            hash_type = hashes[raw_input(prompt).zfill(2)]
        except KeyError:
            print("{}Please select a supported hash type".format(os.linesep))
            continue
        else:
            break

    prompt = "{}Specify the hash to be attacked: ".format(os.linesep)

    while True:
        try:
            user_hash = raw_input(prompt)
        except ValueError:
            print("{}Something is wrong with the format of the hash. Please enter a valid hash".format(os.linesep))
            continue
        else:
            break

    print("{}Cracking...{}".format(os.linesep, os.linesep))  # , flush=True)

    s = connection('localhost', 5005)

    Dict_File = open("Dictionary.txt","r")
    length=len(Dict_File.readlines())/4
    Dict_File = open("Dictionary.txt", "r")
    # length=100
    print length
    # print Dict_File.readlines()[:length]
    s.send(pickle.dumps([hash_type, user_hash ,Dict_File.readlines()[:length]]))

    threading._start_new_thread(getMessage, (s,))

    while True:
        if counter >= 5:
            print "can not find a match password"
            break
        if status != "NOT FOUND":
            print "Password FOUND : " + status
            break

if __name__ == "__main__":
    counter = 0
    status = 'NOT FOUND'
    # bruteForce()
    dictionary_attack()