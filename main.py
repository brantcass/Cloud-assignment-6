# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#cr
from flask import Flask, request, jsonify, send_file, Response
from google.cloud import datastore, storage
import os
import requests
import json
from io import BytesIO
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
#using this to debug
import logging 
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
storage_client = storage.Client()
client = datastore.Client()



# Update the values of the following 3 variables
CLIENT_ID = '5hhCCUMWWhe8zEEhGEqJjnfrZMBtsuij'
CLIENT_SECRET = 'cbE7p0vj2d24zv_MvVO6_t3JJltvBGTBZyD84VqLQ15xN8LdwYogHm5WxD_-IvFD'
DOMAIN = 'dev-gfgp5mih8a2k4ldt.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /businesses to use this API"
logging.basicConfig(level=logging.DEBUG)

#########################
# Get all users
#########################
@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        #verify the JWT 
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']
   
    #query the user entity from Datastore using the 'sub' value
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())

    if (not results):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    user = results[0] 

    #check if the user has the 'admin' role
    user_role = user.get('role')
    if (user_role != 'admin'):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    query = client.query(kind='users')
    results = list(query.fetch())

    users = [{"id": user.key.id, "role": user["role"], "sub": user["sub"]} for user in results if user]

    return jsonify(users), 200

#################################
# Get a user
#################################
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']

    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())

    if(not results):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    current_user = results[0]

    if (current_user.get('role') != 'admin' and current_user.key.id != user_id):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    user_key = client.key('users', user_id)
    user = client.get(user_key)

    if(not user):
        return jsonify({"Error": "Not found"}), 404

    response = {
        "id": user.key.id,
        "role": user["role"],
        "sub": user["sub"]
    }

    if ('avatar_url' in user):
        response['avatar_url'] = user['avatar_url']

    if (user['role'] in ['instructor', 'student']):
        courses = []
        course_query = client.query(kind='courses')
        if user['role'] == 'instructor':
            course_query.add_filter('instructor_id', '=', user.key.id)
        else:
            course_query.add_filter('student_id', '=', user.key.id)
        courses = list(course_query.fetch())
        response['courses'] = [f"http://localhost:8080/courses/{course.key.id}" for course in courses]

    return jsonify(response), 200


#################################
# Create/update a user's avatar
#################################
@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def upload_avatar(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())

    if (not results):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    current_user = results[0]

    if (current_user.key.id != user_id):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    #check if the request includes the key 'file'
    if ('file' not in request.files):
        return jsonify({"Error": "The request body is invalid"}), 400

    file = request.files['file']

    if(not file.filename.endswith('.png')):
        return jsonify({"Error": "The request body is invalid"}), 400

    bucket_name = 'assignment6_photos_cassb'
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(f'avatars/{user_id}.png')
    try:
        blob.upload_from_file(file)
    except Exception as e:
        return jsonify({"Error": str(e)}), 500

    avatar_url = f"{request.url_root}users/{user_id}/avatar"

    user_key = current_user.key
    user = client.get(user_key)
    user['avatar_url'] = avatar_url
    client.put(user)

    response = {
        "avatar_url": avatar_url
    }

    return jsonify(response), 200

#####################
# Get User's avatar
#####################
@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_user_avatar(user_id):

    try:
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())

    if (not results):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    current_user = results[0]

    if(current_user.key.id != user_id):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    user_key = client.key('users', user_id)
    user = client.get(user_key)

    if (not user or 'avatar_url' not in user):
        return jsonify({"Error": "Not found"}), 404

    bucket_name = 'assignment6_photos_cassb'
    blob = storage_client.bucket(bucket_name).blob(f'avatars/{user_id}.png')
    
    try:
        file_data = blob.download_as_bytes()
    except Exception as e:
        return jsonify({"Error": str(e)}), 404

    return send_file(BytesIO(file_data), mimetype='image/png')


#################################
# Delete a user's avatar
#################################

@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_user_avatar(user_id):

    try:
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']

    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())
    current_user = results[0]

    if (current_user.key.id != user_id):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    user_key = client.key('users', user_id)
    user = client.get(user_key)

    #check if the user exists and has an avatar_url
    if(not user or 'avatar_url' not in user):
        return jsonify({"Error": "Not found"}), 404

    #delete the avatar file from Google Cloud Storage
    bucket_name = 'assignment6_photos_cassb' 
    blob = storage_client.bucket(bucket_name).blob(f'avatars/{user_id}.png')
    
    try:
        blob.delete()
    except Exception as e:
        return jsonify({"Error": str(e)}), 500

    del user['avatar_url']
    client.put(user)

    return '', 204

#################################
# Create a course
#################################
@app.route('/courses', methods=['POST'])
def create_course():

    try:
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())
    if (not results):
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    current_user = results[0]

    if (current_user['role'] != 'admin'):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    data = request.get_json()

    required_attributes = ['subject', 'number', 'title', 'term', 'instructor_id']
    if(not all(attr in data for attr in required_attributes)):
        return jsonify({"Error": "The request body is invalid"}), 400

    instructor_key = client.key('users', int(data['instructor_id']))
    instructor = client.get(instructor_key)
    if(not instructor or instructor['role'] != 'instructor'):
        return jsonify({"Error": "The request body is invalid"}), 400

    course_key = client.key('courses')
    new_course = datastore.Entity(key=course_key)
    new_course.update({
        'subject': data['subject'],
        'number': data['number'],
        'title': data['title'],
        'term': data['term'],
        'instructor_id': data['instructor_id'],
        'students': []
    })
    client.put(new_course)

    #create link
    self_url = f"{request.url_root}courses/{new_course.key.id}"

    return jsonify({
        'id': new_course.key.id,
        'subject': data['subject'],
        'number': data['number'],
        'title': data['title'],
        'term': data['term'],
        'instructor_id': data['instructor_id'],
        'self': self_url
    }), 201


#################################
# Get all courses
#################################
@app.route('/courses', methods=['GET'])
def get_courses():

    limit = int(request.args.get('limit', 3))
    offset = int(request.args.get('offset', 0))
    query = client.query(kind='courses')
    query.order = ['subject']
    iterator = query.fetch(limit=limit, offset=offset)
    courses = list(iterator)
    next_offset = offset + limit

    #response with courses and next link
    response_courses = [{
        'id': course.key.id,
        'subject': course['subject'],
        'number': course['number'],
        'title': course['title'],
        'term': course['term'],
        'instructor_id': course['instructor_id'],
        'self': f"{request.url_root}courses/{course.key.id}"
    } for course in courses]

    response = {'courses': response_courses}

    #Add next link if there are more courses to fetch
    if(len(courses) == limit):
        next_url = f"{request.url_root}courses?limit={limit}&offset={next_offset}"
        response['next'] = next_url

    return jsonify(response), 200


#################################
# Get a course
#################################
@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):

    # key using the course ID to fetch the course from datastore
    course_key = client.key('courses', course_id)
    
    course = client.get(course_key)

    if(not course):
        return jsonify({"Error": "Not found"}), 404

    course_data = {
        "id": course.key.id,
        "instructor_id": course["instructor_id"],
        "number": course["number"],
        "self": f"https://{request.host}/courses/{course.key.id}",
        "subject": course["subject"],
        "term": course["term"],
        "title": course["title"]
    }

    return jsonify(course_data), 200

#################################
# Update course
#################################
@app.route('/courses/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    user_results = list(query.fetch())

    if(not user_results or user_results[0]['role'] != 'admin'):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    data = request.get_json()
    if(not data):
        return jsonify({"Error": "The request body is invalid"}), 400

    course_key = client.key('courses', course_id)
    course = client.get(course_key)
    if (not course):
        return jsonify({"Error": "Not found"}), 404

    if ('instructor_id' in data):
        instructor_key = client.key('users', int(data['instructor_id']))
        instructor = client.get(instructor_key)
        if not instructor or instructor['role'] != 'instructor':
            return jsonify({"Error": "Invalid instructor ID"}), 400

    for key, value in data.items():
        if key in ['subject', 'number', 'title', 'term', 'instructor_id']:
            course[key] = value

    client.put(course)
    course_data = {
        "id": course.key.id,
        "subject": course.get("subject"),
        "number": course.get("number"),
        "title": course.get("title"),
        "term": course.get("term"),
        "instructor_id": course.get("instructor_id"),
        "self": request.url
    }

    return jsonify(course_data), 200

 

#################################
# Delete a course
#################################
@app.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):

    try:
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())

    if (not results):
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    current_user = results[0]

    if (current_user['role'] != 'admin'):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    #fetch the course to delete
    course_key = client.key('courses', course_id)
    course = client.get(course_key)

    if (not course):
        return jsonify({"Error": "Not found"}), 404

    enrollment_query = client.query(kind='enrollment')
    enrollment_query.add_filter('course_id', '=', course_id)
    enrollments = list(enrollment_query.fetch())

    for enrollment in enrollments:
        client.delete(enrollment.key)

    client.delete(course_key)

    return '', 204


#################################
# Update enrollment for a course
#################################
@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
def update_enrollment(course_id):
    
    try:
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())

    if (not results):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    current_user = results[0]

    #verify course
    course_key = client.key('courses', course_id)
    course = client.get(course_key)

    if((current_user['role'] != 'admin') and (course['instructor_id'] != current_user.key.id)):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    content = request.get_json()

    if(('add' not in content) or ('remove' not in content)):
        return jsonify({"Error": "Invalid request body"}), 400

    add_students = content['add']
    remove_students = content['remove']
    if(set(add_students) & set(remove_students)):
        return jsonify({"Error": "Enrollment data is invalid"}), 409

    valid_student_ids = set()
    for student_id in (add_students + remove_students):
        student_key = client.key('enrollment', student_id)
        valid_student_ids.add(student_id)

    enrollment_query = client.query(kind='enrollment')
    enrollment_query.add_filter('course_id', '=', course_id)
    enrollments = list(enrollment_query.fetch())
    enrolled_student_ids = {enrollment['student_id'] for enrollment in enrollments}

    #enroll
    for student_id in add_students:
        if student_id not in enrolled_student_ids:
            enrollment_key = client.key('enrollment', f"{course_id}_{student_id}")
            enrollment = datastore.Entity(key=enrollment_key)
            enrollment.update({
                'student_id': student_id,
                'course_id': course_id
            })
            client.put(enrollment)

    #disenroll
    for student_id in remove_students:
        if (student_id in enrolled_student_ids):
            enrollment_key = client.key('enrollment', f"{course_id}_{student_id}")
            client.delete(enrollment_key)
            

    return Response(status = 200)


#################################
# Get enrollment for a course
#################################
@app.route('/courses/<int:course_id>/students', methods=['GET'])
def get_enrollment(course_id):

    try:
        # Verify the JWT
        payload = verify_jwt(request)
    except AuthError as auth_error:
        return jsonify({"Error": "Unauthorized"}), 401

    user_sub = payload['sub']
    
    # Query the user entity from Datastore using the 'sub' value
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())

    if (not results):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    current_user = results[0]
    course_key = client.key('courses', course_id)
    course = client.get(course_key)

    if (not course):
        return jsonify({"Error": "Not found"}), 404

    if (current_user['role'] != 'admin' and course['instructor_id'] != current_user.key.id):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    enrollment_query = client.query(kind='enrollment')
    enrollment_query.add_filter('course_id', '=', course_id)
    enrollments = list(enrollment_query.fetch())
    student_ids = [enrollment['student_id'] for enrollment in enrollments]

    return jsonify(student_ids), 200




# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    
    # Check if the required fields are present
    if not content or 'username' not in content or 'password' not in content:
        return jsonify({"Error": "The request body is invalid"}), 400

    username = content["username"]
    password = content["password"]
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'openid'
    }
    headers = {'content-type': 'application/json'}
    url = f'https://{DOMAIN}/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    
    if r.status_code == 200:
        try:
            response_data = r.json()
            if 'id_token' in response_data:
                return jsonify(token=response_data['id_token']), 200
            else:
                return jsonify({"Error": "Auth0 response does not contain id_token"}), 500
        except ValueError:
            return jsonify({"Error": "Failed to parse Auth0 response as JSON"}), 500
    elif r.status_code == 401:
        return jsonify({"Error": "Unauthorized"}), 401
    else:
        return jsonify({"Error": "Unauthorized"}), 401
        

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

