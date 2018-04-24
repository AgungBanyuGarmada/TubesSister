import itertools
import string
import os
import hashlib
import time
import multiprocessing
import threading
import socket
import pickle


class ServerThread():
    def __init__(self):
        TCP_IP = 'localhost'
        TCP_PORT = 5005

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((TCP_IP, TCP_PORT))
        s.listen(1)
        while 1:
            conn, addr = s.accept()
            print addr, " Connected"
            watribute = pickle.loads(conn.recv(100000))
            if len(watribute) == 5:
                for i in range(watribute[3],watribute[4]+1):
                    threading._start_new_thread(self.work,(conn,watribute[0],watribute[1],watribute[2], i,))
            else:
                length=len(watribute[2])
                length=length/5
                print length
                for i in range(1,6):
                    threading._start_new_thread(self.dictionary_attack,(watribute[0],watribute[1],watribute[2][length*(i-1):(length*i)-1]))

    def generate_hash(self, data):
        """
        Generates a hash of the required type
        :param data: What will be hashed
        :return:
        """
        if self.__hash_type == "ntlm":
            return hashlib.new("md4", data.encode("utf-16le")).hexdigest()

        return hashlib.new(self.__hash_type, data.encode("utf-8")).hexdigest()

    @staticmethod
    def __search_space(charset, maxlength):
        """
        Generates the search space for us to attack using a generator
        We could never pregenerate this as it would take too much time and require godly amounts of memory
        For example, generating a search space with a rough size of 52^8 would take over 50TB of RAM
        :param charset: The character set to generate a search space for
        :param maxlength: Maximum length the search space should be capped at
        :return:
        """
        return (
            ''.join(candidate) for candidate in
            itertools.chain.from_iterable(
                itertools.product(charset, repeat=i) for i in
                range(maxlength, maxlength + 1)
            )
        )

    def attack(self, charset, maxlength):
        """
        Tries all possible combinations in the search space to try and find a match
        :param q: Work queue
        :param charset: The character set to attack
        :param maxlength: Maximum length of the character set to attack
        :return:
        """
        for attempt in self.__search_space(charset, maxlength):
            if self.__hash == self.generate_hash(attempt):
                # q.put("{}Match found! Password is {}{}".format(os.linesep, attempt, os.linesep))
                return attempt
        return "NOT FOUND"


    def work(self,conn, hash_type, hash, charset, maxlength):
        """
        Take the data given to us from some process and kick off the work
        :param work_queue: This is what will give us work from some other process
        :param done_queue: Used to signal the parent from some other process when we are done
        :param charset: The character set to work on
        :param maxlength: Maximum length of the character set
        :return:
        """
        self.__hash_type = hash_type
        self.__hash = hash
        conn.send(self.attack(charset, maxlength))

    def dictionary_attack(self, passw, hash, passwordlist):
        self.__hash_type = hash
        self.__hash = passw
        for attempt in passwordlist:
            print attempt
            if self.__hash == self.generate_hash(attempt):
                return attempt
        return "NOT FOUND"

if __name__ == "__main__":
    server = ServerThread()

