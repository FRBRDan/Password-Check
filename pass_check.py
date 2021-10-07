import requests
import hashlib
from requests.api import request
import sys


# Queries the API with first 5 characters of the hash
def getAPIData(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error: {res.status_code}. Check API.')
    return res


# Traverses over the hashes received in getAPIData(), and checks if there's a match
def getPassLeakCount(hashes, hash_check):     
    hashes = (line.split(':') for line in hashes.text.splitlines())    
    for hash, count in hashes:
        if hash == hash_check:
            return count
    return 0
        

# Converts pass to SHA1 and uses the above methods
def pwnAPICheck(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_chars, end_chars = sha1_password[:5], sha1_password[5:]
    response = getAPIData(first_chars)
    return getPassLeakCount(response, end_chars)
    

def main(args):
    for password in args:
        count = pwnAPICheck(password)
        if count == 0:
            print(f'Password \'{password}\' hasn\'t been hacked and is safe to use.')
        else:
            print(f'Password \'{password}\' has been hacked {count} times.')
    return 'All done.'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

