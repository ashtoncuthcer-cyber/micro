import jwt, os
from datetime import datetime, timedelta, timezone

from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

server.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
server.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
server.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
server.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')
server.config['MYSQL_PORT'] = os.environ.get('MYSQL_PORT')

def createJWT(username, secret, is_admin):
    return jwt.encode(
        {
            'username': username,
            'iat': datetime.now(timezone.utc),
            'exp': datetime.now(timezone.utc) + timedelta(days=1),
            'admin': is_admin
        },
        secret,
        algorithm='HS256'
    )

@server.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth:
        return 'missing credentials', 401
    cur = mysql.connection.cursor()
    res = cur.exec(
        'SELECT email, password FROM user WHERE email = %s', (auth.username, )
    )
    if not res:
        return 'invalid credentials', 401
    email, password = cur.fetchone()
    if email != auth.username or password != password:
        return 'invalid credentials', 401
    return createJWT(auth.username, os.environ.get('JWT_SECRET'), True)

@server.route('/validate', methods=['POST'])
def validate():
    encoded_jwt = request.authorization
    if not encoded_jwt:
        return 'missing credentials', 401
    encoded_jwt = encoded_jwt.split(' ')[1]
    try:
        decoded = jwt.decode(
            encoded_jwt,
            os.environ.get('JWT_SECRET'),
            algorithms=['HS256']
        )
    except:
        return 'not authorized', 403
    return decoded


if __name__ == '__main__':
    server.run(host='0.0.0.0', port=5000)