from flask import Flask, redirect, url_for, request, render_template,session
from flask_oauthlib.client import OAuth
from jose import jws
import urllib.parse
import json, uuid, requests
#https://github.com/Azure-Samples/active-directory-b2c-python-flask-webapp/blob/archive/b2cflaskapp.py
from jws.algos import route

app = Flask(__name__)
app.secret_key = 'Developpement'
app.debug = True
oauth = OAuth(app)

# === Update these values ===========
tenant_id = 'B2CMiro.onmicrosoft.com'
client_id = '8df7094f-b483-4564-bad7-91f70011b821'
client_secret = r'4QJ`{^59dy64XT1\u:oK6a/7'
policy_name = 'B2C_1_miro79_signin'
# ===================================
scopes = ['openid', 'offline_access', client_id]



core_url = 'https://login.microsoftonline.com/tfp/' + tenant_id + '/' + policy_name
refresh_url = 'https://B2CMiro.b2clogin.com/b2cmiro.onmicrosoft.com/oauth2/v2.0/token?p=B2C_1_b2c_signin_signup'
token_url = core_url + '/oauth2/v2.0/token'
authorize_url = core_url + '/oauth2/v2.0/authorize'
keys_url = core_url + '/discovery/keys'

keys_raw = requests.get(keys_url).text
keys = json.loads(keys_raw)

#http://docs.authlib.org/en/latest/client/flask.html#flask-client
microsoft = oauth.remote_app(
    'microsoft',
    consumer_key=client_id,
    consumer_secret=client_secret,
    request_token_params={'scope': scopes},
    base_url='http://ignore',  # We won't need this
    request_token_url=None,
    access_token_method='POST',
    access_token_url=token_url,
    authorize_url=authorize_url
)

@app.route('/')
def index():
	return render_template('hello.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    
    if 'microsoft_token' in session:
        return redirect(url_for('me'))

    # Generate the guid to only accept initiated logins
    guid = uuid.uuid4()
    session['state'] = guid

    print(microsoft.authorize(callback=url_for('authorized', _external=True), state=guid))
    return microsoft.authorize(callback=url_for('authorized', _external=True), state=guid)

@app.route('/login/authorized')
def authorized():
    
    response = microsoft.authorized_response()
    print(response)

    if response is None:
        return "Access Denied: Reason=%s\nError=%s" % (
            response.get('error'),
            request.get('error_description')
        )

    # Check response for state
    print("Response: " + str(response))
    if str(session['state']) != str(request.args['state']):
        raise Exception('State has been messed with, end authentication')

    
    code = request.args['code']
    access_token = response['access_token']
    refresh_token = response['refresh_token']
    id_token = response['id_token']
    session['microsoft_token'] = (access_token, '')
    session['id_token'] = (id_token, '')
    session['code'] = (code, '')
    session['refresh_token'] = refresh_token
    session['claims'] = json.loads(jws.verify(access_token, keys, algorithms=['RS256']))
    session['id_token_decoded'] = json.loads(jws.verify(id_token, keys, algorithms=['RS256']))
    return redirect(url_for('me'))


@app.route('/me')
def me():
    token = session['microsoft_token'][0]
    claims = session['claims']
    raw = session['microsoft_token']
    id_token = session['id_token']
    id_token_decoded = session['id_token_decoded']
    code = session['code']
    refresh_token = session['refresh_token']
    return render_template('me.html', me=str(claims),raw=raw,id_token=id_token,id_token_decoded=id_token_decoded, code=code,
                           refresh_token=refresh_token)


@app.route('/refresh', methods=['POST', 'GET'])
def refresh_token():
    # Get a refresh_token

    params = urllib.parse.urlencode({'client_id': client_id,
                                     'client_secret': client_secret,
                                     'grant_type': 'refresh_token',
                                     'refresh_token': session['refresh_token'],
                                     })

    r = requests.post(refresh_url, data=params, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    return r.content


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    requests.session().close()
    return redirect(url_for('index'))

@microsoft.tokengetter
def get_microsoft_oauth_token():
    return session.get('microsoft_token')

if __name__ == '__main__':
    app.run()
