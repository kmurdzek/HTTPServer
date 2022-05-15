import socket
import signal
import sys
import random
import datetime
# Read a command line argument for the port where the server
# must run.
port = 8080
if len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    print("Using default port 8080")

# Start a listening server socket on the port
sock = socket.socket()
sock.bind(('', port))
sock.listen(2)

# Contents of pages we will serve.
# Login form
login_form = """
   <form action = "http://localhost:%d" method = "post">
   Name: <input type = "text" name = "username">  <br/>
   Password: <input type = "text" name = "password" /> <br/>
   <input type = "submit" value = "Submit" />
   </form>
""" % port
# Default: Login page.
login_page = "<h1>Please login</h1>" + login_form
# Error page for bad credentials
bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
# Successful logout
logout_page = "<h1>Logged out successfully</h1>" + login_form
# A part of the page that will be displayed after successful
# login or the presentation of a valid cookie
success_page = """
   <h1>Welcome!</h1>
   <form action="http://localhost:%d" method = "post">
   <input type = "hidden" name = "action" value = "logout" />
   <input type = "submit" value = "Click here to logout" />
   </form>
   <br/><br/>
   <h1>Your secret data is here:</h1>
""" % port

# Helper functions
# Printing.


def print_value(tag, value):
    print "Here is the", tag
    print "\"\"\""
    print value
    print "\"\"\""
    print

# Signal handler for graceful exit


def sigint_handler(sig, frame):
    print('Finishing up by closing listening socket...')
    sock.close()
    sys.exit(0)


# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)


# TODO: put your application logic here!
# Read login credentials for all the users
# Read secret data of all the users

def check_username_password(check):
    lines = []
    with open('passwords.txt') as f:
        lines = f.readlines()

        for line in lines:
            line = line.strip()
            if (line == check):
                return True
    return False


def get_secret(username):
    lines = []
    with open('secrets.txt') as f:
        lines = f.readlines()

        for line in lines:
            line = line.strip()
            secret = line.split(' ', 1)
            print(secret[0])
            print(secret[1])
            if (username == secret[0]):
                return secret[1]


cookie_dict = {}

# Loop to accept incoming HTTP connections and respond.
while True:

    client, addr = sock.accept()
    req = client.recv(1024)

    # Let's pick the headers and entity body apart
    header_body = req.split('\r\n\r\n')
    headers = header_body[0]
    headers = headers.split("\r\n")
    # this loop just iterates the headers to see if there is a cookie header sets it to cookie_id
    cookie_id = None
    for i in headers:
        if(i.find("Cookie:") != -1):
            temp = i.split("=")
            cookie_id = temp[1]

    body = '' if len(header_body) == 1 else header_body[1]
    print_value('headers', headers)

    print_value('entity body', body)
    headers_to_send = ''
    # TODO: Put your application logic here!
    # Parse headers and body and perform various actions
    # body is the string in form username=""&password=""

    if (body == '' and cookie_id == None or cookie_id == '-1'):
        # no cookies and empty body
        print("get stament")
        print(body)
        html_content_to_send = login_page

    elif(body == "action=logout"):
        # logout and disable the current cookie
        html_content_to_send = login_page
        cookie_id = None
        expires = datetime.datetime.now()
        headers_to_send += "Set-Cookie: token =; expires=Thu, 01 Jan 1970 00:00:00 GMT" + \
            str(expires) + "\r\n"

        """
        Now delete the cookie from the
        """

    elif(cookie_id is not None):
        # find the cookie in the dict sign in that username
        print(cookie_dict, cookie_id)
        if(cookie_dict.has_key(cookie_id)):
            # means that a user exists with this cookie
            headers_to_send += "Cookie: token =" + str(cookie_id) + "\r\n"
            secret = get_secret(cookie_dict[cookie_id])
            print(secret)
            html_content_to_send = success_page + secret
        else:
            # bad user case
            print("cookie not in dict")
            html_content_to_send = bad_creds_page
    else:
        # means no cookies just a fresh log in
        split_string = body.partition('&')
        print(split_string)
        username = split_string[0][9:]
        password = split_string[2][9:]

        check = username + " " + password
        print(check)
        valid_login = check_username_password(check)
        print(valid_login)
        # if it is a valid login and the cookie is already set then leave it
        if (valid_login):
            rand_val = random.getrandbits(64)
            # store the username and the cookie together
            # store the cookie in the dict with the username
            cookie_dict[str(rand_val)] = username
            headers_to_send += "Set-Cookie: token =" + str(rand_val) + "\r\n"
            secret = get_secret(username)
            print(secret)
            html_content_to_send = success_page + secret

        if (not valid_login):
            html_content_to_send = bad_creds_page
    # You need to set the variables:
    # (1) `html_content_to_send` => add the HTML content you'd
    # like to send to the client.
    # Right now, we just send the default login page.

    # But other possibilities exist, including
    # html_content_to_send = success_page + <secret>
    # html_content_to_send = bad_creds_page
    # html_content_to_send = logout_page

    # (2) `headers_to_send` => add any additional headers
    # you'd like to send the client?
    # Right now, we don't send any extra headers.

    # Construct and send the final response
    response = 'HTTP/1.1 200 OK\r\n'
    response += headers_to_send
    response += 'Content-Type: text/html\r\n\r\n'
    response += html_content_to_send
    print_value('response', response)
    client.send(response)
    client.close()

    print "Served one request/connection!"
    print

# We will never actually get here.
# Close the listening socket
sock.close()
