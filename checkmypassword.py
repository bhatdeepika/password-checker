import hashlib
import requests  # used to make a request similar to  hitting the browser with a request
# api uses hash functions SHA1 algorithm
import sys
# '''Gonna convert the below set of code to a function'''

# url = 'https://api.pwnedpasswords.com/range/' + 'E6B6A'
# response = requests.get(url)
# print(response)

# gets the data from the API


def request_api_data(hash_char):  # grabs the first5 char of hash response
    # appends hash of first5 char along with the url
    url = 'https://api.pwnedpasswords.com/range/' + hash_char
    res = requests.get(url)  # it gives us the result of tailed hashes
    if res.status_code != 200:
        raise RuntimeError(f'Error {res.status_code},check the API')
    return res  # returns the list of tailed hashes

# Function to grab  the tail of hashes and count of it


# hashes are response that is grabbed from the API (the total tail hashes) and hash_to_check is our original tail
def get_password_check_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# def read_res(responsee):
#     print(responsee.text)  # passwords that match the beginning of the hash

# Function to Check if the provided password was pwned


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # grab first 5 char and tail
    first5_char, tail = sha1password[:5], sha1password[5:]
    # print(first5_char, tail)
    # grabs first 5 char of password and gives it to request api data function
    response = request_api_data(first5_char)  # response of first5 char
    # print(response.content)
    return get_password_check_count(response, tail)  # we pass the the


def main(text):
    for password in text:
        count_of_password = pwned_api_check(password)
        if count_of_password:
            print(
                f'{password} was found {count_of_password} times. Please change it ! ')
        else:
            print(f'Password was not found, please carry on !')
    return 'Done !'


with open('./text.txt', mode='r') as my_file:
    text = my_file.readlines()

if __name__ == '__main__':
    sys.exit(main(text))
