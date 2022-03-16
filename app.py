from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisthesecrectkey'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')  # http://127.0.0.1:5000/route?token=hhijiuujbhij

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

            data = jwt.decode(token, app.config['SECRET_KEY'])
            print(data)

        return f(*args, **kwargs)

    return decorated


@app.route('/unprotected')
def unprotected():
    return jsonify({'message': 'Anyone can  view this!'})


@app.route('/protected')
@token_required
def protected():
    return jsonify({'message': 'Hello Python'})


@app.route('/login')
def login():
    auth = request.authorization

    if auth.password == 'Prati@1234':
        token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=180)},
                           app.config['SECRET_KEY'])

        return jsonify({'token': token})

    return make_response('Could not verify!!', 401, {'www-Authenticate': 'Basic realm=Login Requried"'})


if __name__ == '__main__':
    app.run(debug=True)
