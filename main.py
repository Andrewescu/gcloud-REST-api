from theFuncts import *
import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from urllib.request import urlopen

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, make_response, jsonify

from jose import jwt
from flask import request


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

oauth.register(
    'auth0',
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    api_base_url="https://" + env.get("AUTH0_DOMAIN"),
    access_token_url="https://" + env.get("AUTH0_DOMAIN") + "/oauth/token",
    authorize_url="https://" + env.get("AUTH0_DOMAIN") + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
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

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ env.get("AUTH0_DOMAIN") +"/.well-known/jwks.json")
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
                audience=env.get("AUTH0_CLIENT_ID"),
                issuer="https://"+ env.get("AUTH0_DOMAIN") +"/"
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





@app.route("/")
def home():
    if (session):
        userData = session.get("user")
        if (uniqueUserID(userData["userinfo"]["sub"])):
            addUser(userData["userinfo"]["name"], userData["userinfo"]["sub"])
    return render_template("home.html", session=session.get("user"))


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


############### BEGIN ENTITY ROUTES

### BEGIN USER ROUTE

@app.route('/users', methods=['GET'])
def Users_getAll():

    if request.method == 'GET':
        allUsers = json.loads(getAllUsers())
        if 'application/json' in request.accept_mimetypes:
            res = make_response(json.dumps(allUsers))
            res.mimetype = 'application/json'
            res.status_code = 200
            return (res)

        else:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)

    else:
        errorMethod = {"error": "Method Not Allowed"}
        res = make_response(json.dumps(errorMethod))
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 405
        return res

### END USER ROUTE

### BEGIN BOAT ROUTES

# this route allows boat creation via Post, all route calls must accompany a valid JWT
# boat created via Post will be linked to userID (sub) from provided JWT
# get request will provide all boats related to userID (sub) from provided JWT
@app.route('/boats', methods=['POST','GET', 'PATCH', 'PUT', 'DELETE'])
def boats_get_post():

    # checks for valid JWT
    try:
        payload = verify_jwt(request)
        uniqueID = payload["sub"]
    except:
        return (jsonify({"error": "Requires valid JWT"}), 401)

    # returns all boats related to JWT userID (sub)
    if request.method == 'GET':

        args = request.args
        args.get("limit", default="5", type=str)
        args.get("offset", default="0", type=str)
        args = args.to_dict()

        allBoats = json.loads(getAllBoats())
        userBoats = []
        for boat in allBoats:
            if uniqueID == boat["uniqueID"]:
                userBoats.append(boat)

        if (len(args) == 0):
            userBoats = userBoats
            selfBase = request.base_url
            theNext = selfBase   + "?limit=5&offset=5"
            responseList = []
            
            if (len(userBoats) > 5):
                responseList.append({"count": len(userBoats) ,"next": theNext})
            else:
                responseList.append({"count": len(userBoats)})
                
            res = make_response(json.dumps([responseList, userBoats[0:5]]))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 200
            return res   
    
        else:
            userBoats = userBoats
            theLimit = args["limit"]
            theOffset = args["offset"]

            # dont return next if there arent anymore entries to paginate
            if ((int(theOffset)+ int(theLimit)) >= len(userBoats)):
                intOffset = int(theOffset)
                responseList = []
                responseList.append({"count": len(userBoats)})
                res = make_response(json.dumps([responseList, userBoats[intOffset:]]))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 200
                return res    
            else:
                responseList = []
                selfBase = request.base_url
                intOffset = int(theOffset)
                nextOffset = int(theLimit) + int(theOffset)
                theNext = selfBase  + f"?limit={args['limit']}&offset={nextOffset}"
                responseList.append({"count": len(userBoats), "next": theNext})
                res = make_response(json.dumps([responseList, userBoats[intOffset:nextOffset]]))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 200
                return res    
    
    # creates boat related to JWT userID (sub)
    elif request.method == 'POST':

        # request must be JSON                                    
        if 'application/json' not in request.mimetype:     # request.mimetype gets the media type of the request object 
            errorMIME = {"Error": "Unsupported Media Type"} # if that mimetype isnt json, we return unsupported type 415
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 415
            return (res)

        # response must accept JSON
        if 'application/json' not in request.accept_mimetypes:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)

        # attempts to load request
        try:
            content = request.get_json()
        except:
            errorEmptyJson = {"Error": "Bad Request"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # ensures request only has these attributes
        checkArr = ["name", "length", "boatType"]
        for key in content:
            if key not in checkArr:
                errorExtraAtt = {"Error":  "The request object has incorrect attributes" }
                res = make_response(json.dumps(errorExtraAtt))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 400
                return res

        # ensures post request has correct amount of attributes (3)
        if (len(content) != 3):
            errorExtraAtt = {"Error":  "The request object doesn't have the correct amount of attributes" }
            res = make_response(json.dumps(errorExtraAtt))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # ensures all of attributes are present
        if "name" and "boatType" and "length"  not in content:
            errorMissingAtt = {"Error":  "The request object is missing at least one of the required attributes" }
            res = make_response(json.dumps(errorMissingAtt))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # verifies name is within accepted parameters
        if verifyName(content) != 0:
            errorName = {"error": verifyName(content)}
            res = make_response(json.dumps(errorName))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # verifies boatType is within accepted parameters
        if verifyType(content) != 0:
            errorType = {"error": verifyType(content)}
            res = make_response(json.dumps(errorType))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # verifies length is within accepted parameters
        if verifyLength(content) != 0:
            errorLength = {"error": verifyLength(content)}
            res = make_response(json.dumps(errorLength))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # verifies boat name is unique
        if uniqueBoatName(content["name"]) != 0:
            errorUnique = {"error": uniqueBoatName(content["name"])}
            res = make_response(json.dumps(errorUnique))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 403
            return res

        # if all those tests succeed, return boat as JSON with 201 created code
        selfBase = request.base_url
        boat = addBoat(content["name"], content["boatType"], content["length"], uniqueID, selfBase)
        res = make_response(boat)
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 201
        return (res)

    # run if other request method is called
    else:
        errorMethod = {"error": "Method Not Allowed"}
        res = make_response(json.dumps(errorMethod))
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 405
        return res


# this route allows modification of boat attributes that are not related to entity "parkingSpot"
# which includes name, boatType, and length
# must include valid JWT to access these routes and can only edit boat associated with that specific user
@app.route('/boats/<id>', methods=['PATCH','PUT','DELETE','GET', 'POST'])
def boats_patch_delete_get(id):

    # checks for valid JWT
    try:
        payload = verify_jwt(request)
        uniqueID = payload["sub"]
    except:
        return (jsonify({"error": "Requires valid JWT"}), 401)

    # PATCH allows update of subset of attributes, leaving others left unchanged
    if request.method == 'PATCH':

        # if boat with this ID doesn't exist return this
        trueBoat = getBoat(id)
        if trueBoat == False:
            errorNoBoat = {"Error": "No boat with this boat_id exists"}
            res = make_response(json.dumps(errorNoBoat))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        trueBoat = json.loads(trueBoat)
        # if uniqueID from boat doesn't match JWT return error 401
        if (str(trueBoat["uniqueID"]) != str(uniqueID)):
            errorNoBoat = {"Error": "Boat uniqueID doesn't match JWT"}
            res = make_response(json.dumps(errorNoBoat))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 401
            return res

        # if the mimetype isnt json, we return unsupported type 415
        if 'application/json' not in request.mimetype:     
            errorMIME = {"Error": "Unsupported Media Type"} 
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 415
            return (res)
             
        # if the accepted mimetype isnt json we return 406
        if 'application/json' not in request.accept_mimetypes:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)
             

        # load request object
        try:
            content = request.get_json()
        except:
            errorEmptyJson = {"Error": "Bad Request"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
             

        if len(content) == 0:
            errorEmptyJson = {"Error": "No Attribute(s) found"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
             
        # returns error if "id" attribute is edited
        if "id" in content:
            errorID = {"Error": "Attribute id isn't editable"}
            res = make_response(json.dumps(errorID))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
            
        # ensures only name, length, and-or boatType attribute is edited
        checkArr = ["name", "length", "boatType"]
        for key in content:
            if key not in checkArr:
                errorExtraAtt = {"Error":  "The request object has incorrect attributes" }
                res = make_response(json.dumps(errorExtraAtt))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 400
                return res

         # for loop verifies name, length, and boatType are all valid strings
        for key in content:
            if key == "name":
                if verifyName(content) != 0:
                    errorName = {"error": verifyName(content)}
                    res = make_response(json.dumps(errorName))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res
                    
                if uniqueBoatName(content["name"]) != 0:
                    errorUnique = {"error": uniqueBoatName(content["name"])}
                    res = make_response(json.dumps(errorUnique))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 403
                    return res

            if key == "boatType":
                if verifyType(content) != 0:
                    errorType = {"error": verifyType(content)}
                    res = make_response(json.dumps(errorType))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res

            if key == "length":
                if verifyLength(content) != 0:
                    errorLength = {"error": verifyLength(content)}
                    res = make_response(json.dumps(errorLength))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res

        editedBoat = json.loads(editBoat(id, content))
        output = {"message": "See Location Header for boat URL"}
        res = make_response(json.dumps(output))
        res.headers['Location'] = editedBoat["self"]
        res.mimetype = 'application/json'
        res.status_code = 303
        return (res)
             
    # PUT must update all attributes
    # The URL of the updated boat must be included in the Location header.
    elif request.method == 'PUT':

        # returns 404 if boat doesn't exist
        trueBoat = getBoat(id)
        if trueBoat == False:
            errorNoBoat = {"Error": "No boat with this boat_id exists"}
            res = make_response(json.dumps(errorNoBoat))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        trueBoat = json.loads(trueBoat)

        # if uniqueID from boat doesn't match JWT return error 401
        if (str(trueBoat["uniqueID"]) != str(uniqueID)):
            errorNoBoat = {"Error": "Boat uniqueID doesn't match JWT"}
            res = make_response(json.dumps(errorNoBoat))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 401
            return res

        # request.mimetype gets the media type of the request object 
        if 'application/json' not in request.mimetype:     
            errorMIME = {"Error": "Unsupported Media Type"} 
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 415
            return (res)

        # if accepted mimetype isn't json, return 406
        if 'application/json' not in request.accept_mimetypes:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)
            # return (json.dumps(errorMIME), 406)

        # load request object
        try:
            content = request.get_json()
        except:
            errorEmptyJson = {"Error": "Bad Request"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
            
        # if request is empty return error
        if len(content) == 0:
            errorEmptyJson = {"Error": "No Attribute(s) found"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
            
        # return error if id is edited
        if "id" in content:
            errorID = {"Error": "Attribute id isn't editable"}
            res = make_response(json.dumps(errorID))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # return error if other attributes besides name, length, and boatType are edited
        checkArr = ["name", "length", "boatType"]
        for key in content:
            if key not in checkArr:
                errorExtraAtt = {"Error":  "The request object has incorrect attributes" }
                res = make_response(json.dumps(errorExtraAtt))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 400
                return res
                # return(json.dumps(errorExtraAtt), 400)
        
        # ensures request content has all the attributes required for put request
        if (len(content) != 3):
            errorExtraAtt = {"Error":  "The request object doesn't have the right amount attributes (3)" }
            res = make_response(json.dumps(errorExtraAtt))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
            
        # for loops verifies name, boatType, and length
        for key in content:
            if key == "name":
                if verifyName(content) != 0:
                    errorName = {"error": verifyName(content)}
                    res = make_response(json.dumps(errorName))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res
                    
                if uniqueBoatName(content["name"]) != 0:
                    errorUnique = {"error": uniqueBoatName(content["name"])}
                    res = make_response(json.dumps(errorUnique))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 403
                    return res
                    
            if key == "boatType":
                if verifyType(content) != 0:
                    errorType = {"error": verifyType(content)}
                    res = make_response(json.dumps(errorType))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res
                    
            if key == "length":
                if verifyLength(content) != 0:
                    errorLength = {"error": verifyLength(content)}
                    res = make_response(json.dumps(errorLength))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res


        editedBoat = json.loads(editBoat(id, content))
        output = {"message": "See Location Header for boat URL"}
        res = make_response(json.dumps(output))
        res.headers['Location'] = editedBoat["self"]
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 303
        return (res)

    elif request.method == 'DELETE':

        trueBoat = getBoat(id)
        trueBoat = json.loads(trueBoat)
        # if uniqueID from boat doesn't match JWT return error 401
        if (str(trueBoat["uniqueID"]) != str(uniqueID)):
            errorNoBoat = {"Error": "Boat uniqueID doesn't match JWT"}
            res = make_response(json.dumps(errorNoBoat))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 401
            return res


        theBoat = getBoat(id)
        if (theBoat == False):
            message = {"Error": "No boat with this boat id exists"}
            res = make_response(json.dumps(message))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res
        else:
            theBoat = json.loads(getBoat(id))
            if theBoat["location"] != "At Sea":
                try:
                    editParkingSpot(theBoat["location"], {"boat": "Empty"})
                except:
                    pass
            deleteBoat(id)
            return ("",204)

    elif request.method == 'GET':

        trueBoat = getBoat(id)
        trueBoat = json.loads(trueBoat)
        # if uniqueID from boat doesn't match JWT return error 401
        if (str(trueBoat["uniqueID"]) != str(uniqueID)):
            errorNoBoat = {"Error": "Boat uniqueID doesn't match JWT"}
            res = make_response(json.dumps(errorNoBoat))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 401
            return res

        specificBoat = getBoat(id)
        if (specificBoat == False):
            message = {"Error": "No boat with this boat_id exists"}
            res = make_response(json.dumps(message))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        specificBoat = json.loads(getBoat(id))
        if 'application/json' in request.accept_mimetypes:
            res = make_response(json.dumps(specificBoat))
            res.mimetype = 'application/json'
            res.status_code = 200
            return (res)

        else:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)

    else:
        errorMethod = {"error": "Method Not Allowed"}
        res = make_response(json.dumps(errorMethod))
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 405
        return res

### END BOAT ROUTES

### BEGIN PARKINGSPOT ROUTES

# this route allows parkingSpot creation via Post, all route calls must accompany a valid JWT
# parkingSpot created via Post isn't linked to userID (sub), no JWT required
# get request will provide all parkingSpot 

# @app.route("/<parameter>/<optional_parameter>")
# @app.route("/<parameter>")
# def route(parameter, optional_parameter="Default Value"):

#     return parameter + " " + optional_parameter

@app.route('/parkingSpots', methods=['POST','GET', 'PATCH', 'PUT', 'DELETE'])
def parkingSpots_get_post():


    if request.method == 'GET':
        args = request.args
        args.get("limit", default="5", type=str)
        args.get("offset", default="0", type=str)
        args = args.to_dict()

        if (len(args) == 0):
            allParkingSpots = json.loads(getAllParkingSpots())
            selfBase = request.base_url
            theNext = selfBase   + "?limit=5&offset=5"
            responseList = []
            
            if (len(allParkingSpots) > 5):
                responseList.append({"count": len(allParkingSpots) ,"next": theNext})
            else:
                responseList.append({"count": len(allParkingSpots)})
            res = make_response(json.dumps([responseList, allParkingSpots[0:5]]))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 200
            return res    

        else:
            allParkingSpots = json.loads(getAllParkingSpots())
            theLimit = args["limit"]
            theOffset = args["offset"]

            # dont return next if there arent anymore entries to paginate
            if ((int(theOffset)+ int(theLimit)) >= len(allParkingSpots)):
                intOffset = int(theOffset)
                responseList = []
                responseList.append({"count": len(allParkingSpots)})
                res = make_response(json.dumps([responseList, allParkingSpots[intOffset:]]))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 200
                return res    
            else:
                responseList = []
                selfBase = request.base_url
                intOffset = int(theOffset)
                nextOffset = int(theLimit) + int(theOffset)
                theNext = selfBase  + f"?limit={args['limit']}&offset={nextOffset}"
                responseList.append({"count": len(allParkingSpots), "next": theNext})
                res = make_response(json.dumps([responseList, allParkingSpots[intOffset:nextOffset]]))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 200
                return res    

    
    # creates a parkingSpot 
    elif request.method == 'POST':

        # request must be JSON                                    
        if 'application/json' not in request.mimetype:     
            errorMIME = {"Error": "Unsupported Media Type"} 
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 415
            return (res)

        # response must accept JSON
        if 'application/json' not in request.accept_mimetypes:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)

        # attempts to load request
        try:
            content = request.get_json()
        except:
            errorEmptyJson = {"Error": "Bad Request"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # ensures request only has these attributes
        checkArr = ["name", "address", "cost"]
        for key in content:
            if key not in checkArr:
                errorExtraAtt = {"Error":  "The request object has incorrect attributes" }
                res = make_response(json.dumps(errorExtraAtt))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 400
                return res

        # ensures post request has correct amount of attributes (3)
        if (len(content) != 3):
            errorExtraAtt = {"Error":  "The request object doesn't have the correct amount of attributes" }
            res = make_response(json.dumps(errorExtraAtt))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # ensures all of attributes are present
        if "name" and "address" and "cost"  not in content:
            errorMissingAtt = {"Error":  "The request object is missing at least one of the required attributes" }
            res = make_response(json.dumps(errorMissingAtt))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # verifies name is within accepted parameters
        if verifyName(content) != 0:
            errorName = {"error": verifyName(content)}
            res = make_response(json.dumps(errorName))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # verifies boatType is within accepted parameters
        if verifyaddress(content) != 0:
            errorType = {"error": verifyaddress(content)}
            res = make_response(json.dumps(errorType))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # verifies length is within accepted parameters
        if verifyCost(content) != 0:
            errorLength = {"error": verifyCost(content)}
            res = make_response(json.dumps(errorLength))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # verifies parkingSpot address is unique
        if uniqueParkingSpotName(content["name"]) != 0:
            errorUnique = {"error": uniqueParkingSpotName(content["name"])}
            res = make_response(json.dumps(errorUnique))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 403
            return res

        # if all those tests succeed, return parkingSpot as JSON with 201 created code
        selfBase = request.base_url
        parkingSpot = addParkingSpot(content["name"], content["address"], content["cost"], selfBase)
        res = make_response(parkingSpot)
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 201
        return (res)

    # run if other request method is called
    else:
        errorMethod = {"error": "Method Not Allowed"}
        res = make_response(json.dumps(errorMethod))
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 405
        return res


# this route allows modification of parkingSpot attributes that are not related to entity "boat"
# which includes name, address, and cost\
@app.route('/parkingSpots/<id>', methods=['PATCH','PUT','DELETE','GET', 'POST'])
def parkingSpots_patch_delete_get(id):


    # PATCH allows update of subset of attributes, leaving others left unchanged
    if request.method == 'PATCH':

        # if parkingSpot with this ID doesn't exist return this
        trueParkingSpot = getParkingSpot(id)
        if trueParkingSpot == False:
            errorNoParkingSpot = {"Error": "No ParkingSpot with this ParkingSpot_id exists"}
            res = make_response(json.dumps(errorNoParkingSpot))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        trueParkingSpot = json.loads(trueParkingSpot)

        # if the mimetype isnt json, we return unsupported type 415
        if 'application/json' not in request.mimetype:     
            errorMIME = {"Error": "Unsupported Media Type"} 
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 415
            return (res)
             
        # if the accepted mimetype isnt json we return 406
        if 'application/json' not in request.accept_mimetypes:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)
             

        # load request object
        try:
            content = request.get_json()
        except:
            errorEmptyJson = {"Error": "Bad Request"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
             

        if len(content) == 0:
            errorEmptyJson = {"Error": "No Attribute(s) found"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
             
        # returns error if "id" attribute is edited
        if "id" in content:
            errorID = {"Error": "Attribute id isn't editable"}
            res = make_response(json.dumps(errorID))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
            
        # ensures only name, address, and-or cost attribute is edited
        checkArr = ["name", "address", "cost"]
        for key in content:
            if key not in checkArr:
                errorExtraAtt = {"Error":  "The request object has incorrect attributes" }
                res = make_response(json.dumps(errorExtraAtt))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 400
                return res

         # for loop verifies name, address, and cost are all valid strings
        for key in content:
            if key == "name":
                if verifyName(content) != 0:
                    errorName = {"error": verifyName(content)}
                    res = make_response(json.dumps(errorName))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res
                    
                if uniqueParkingSpotName(content["name"]) != 0:
                    errorUnique = {"error": uniqueParkingSpotName(content["name"])}
                    res = make_response(json.dumps(errorUnique))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 403
                    return res

            if key == "address":
                if verifyaddress(content) != 0:
                    errorType = {"error": verifyaddress(content)}
                    res = make_response(json.dumps(errorType))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res

            if key == "cost":
                if verifyCost(content) != 0:
                    errorLength = {"error": verifyCost(content)}
                    res = make_response(json.dumps(errorLength))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res

        editedParkingSpot = json.loads(editParkingSpot(id, content))
        output = {"message": "See Location Header for parkingSpot URL"}
        res = make_response(json.dumps(output))
        res.headers['Location'] = editedParkingSpot["self"]
        res.mimetype = 'application/json'
        res.status_code = 303
        return (res)
             
    # PUT must update all attributes
    # The URL of the updated parkingSpot must be included in the Location header.
    elif request.method == 'PUT':

        # returns 404 if parkingSpot doesn't exist
        trueParkingSpot = getParkingSpot(id)
        if trueParkingSpot == False:
            errorNoParkingSpot = {"Error": "No parkingSpot with this parkingSpot_id exists"}
            res = make_response(json.dumps(errorNoParkingSpot))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        trueParkingSpot = json.loads(trueParkingSpot)

        # request.mimetype gets the media type of the request object 
        if 'application/json' not in request.mimetype:     
            errorMIME = {"Error": "Unsupported Media Type"} 
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 415
            return (res)

        # if accepted mimetype isn't json, return 406
        if 'application/json' not in request.accept_mimetypes:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)
            # return (json.dumps(errorMIME), 406)

        # load request object
        try:
            content = request.get_json()
        except:
            errorEmptyJson = {"Error": "Bad Request"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
            
        # if request is empty return error
        if len(content) == 0:
            errorEmptyJson = {"Error": "No Attribute(s) found"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
            
        # return error if id is edited
        if "id" in content:
            errorID = {"Error": "Attribute id isn't editable"}
            res = make_response(json.dumps(errorID))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # return error if other attributes besides name, address, and cost are edited
        checkArr = ["name", "address", "cost"]
        for key in content:
            if key not in checkArr:
                errorExtraAtt = {"Error":  "The request object has incorrect attributes" }
                res = make_response(json.dumps(errorExtraAtt))
                res.headers['Content-Type'] = 'application/json'
                res.status_code = 400
                return res
        
        # ensures request content has all the attributes required for put request
        if (len(content) != 3):
            errorExtraAtt = {"Error":  "The request object doesn't have the right amount attributes (3)" }
            res = make_response(json.dumps(errorExtraAtt))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res
            
        # for loops verifies name, address, and cost
        for key in content:
            if key == "name":
                if verifyName(content) != 0:
                    errorName = {"error": verifyName(content)}
                    res = make_response(json.dumps(errorName))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res
                    
                if uniqueParkingSpotName(content["name"]) != 0:
                    errorUnique = {"error": uniqueParkingSpotName(content["name"])}
                    res = make_response(json.dumps(errorUnique))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 403
                    return res
                    
            if key == "address":
                if verifyaddress(content) != 0:
                    errorType = {"error": verifyaddress(content)}
                    res = make_response(json.dumps(errorType))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res
                    
            if key == "cost":
                if verifyCost(content) != 0:
                    errorLength = {"error": verifyCost(content)}
                    res = make_response(json.dumps(errorLength))
                    res.headers['Content-Type'] = 'application/json'
                    res.status_code = 400
                    return res


        editedParkingSpot = json.loads(editParkingSpot(id, content))
        output = {"message": "See Location Header for parkingSpot URL"}
        res = make_response(json.dumps(output))
        res.headers['Location'] = editedParkingSpot["self"]
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 303
        return (res)

    elif request.method == 'DELETE':
        theParkingSpot = getParkingSpot(id)
        if (theParkingSpot == False):
            message = {"Error": "No parkingSpot with this parkingSpot id exists"}
            res = make_response(json.dumps(message))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res
        else:
            theParkingSpot = json.loads(theParkingSpot)
            if (theParkingSpot["boat"] != "Empty"):
                editBoat(theParkingSpot["boat"], {"location": "At Sea"})
            deleteParkingSpot(id)
            return ("",204)

    elif request.method == 'GET':

        specificParkingSpot = getParkingSpot(id)
        if (specificParkingSpot == False):
            message = {"Error": "No parkingSpot with this parkingSpot_id exists"}
            res = make_response(json.dumps(message))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        specificParkingSpot = json.loads(getParkingSpot(id))
        if 'application/json' in request.accept_mimetypes:
            res = make_response(json.dumps(specificParkingSpot))
            res.mimetype = 'application/json'
            res.status_code = 200
            return (res)

        else:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)

    else:
        errorMethod = {"error": "Method Not Allowed"}
        res = make_response(json.dumps(errorMethod))
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 405
        return res

### END PARKINGSPOT ROUTES


# takes post request wtih
#   {
#    "boatID": boatDataStoreID
#    "parkingSpotID": parkingSpotDataStoreID
#    }
@app.route('/assignParkingSpot', methods=['PATCH','PUT','DELETE','GET', 'POST'])
def assignSpot_patch():
    if request.method == 'PATCH':

        # load request object
        try:
            content = request.get_json()
        except:
            errorEmptyJson = {"Error": "Bad Request"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # if boat with this ID doesn't exist return this
        trueBoat = getBoat(content["boatID"])
        if trueBoat == False:
            errorNoBoat = {"Error": "No boat with this boat_id exists"}
            res = make_response(json.dumps(errorNoBoat))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        # if parkingSpot with this ID doesn't exist return this
        trueParkingSpot = getParkingSpot(content["parkingSpotID"])
        if trueParkingSpot == False:
            errorNoParkingSpot = {"Error": "No ParkingSpot with this ParkingSpot_id exists"}
            res = make_response(json.dumps(errorNoParkingSpot))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        # if the mimetype isnt json, we return unsupported type 415
        if 'application/json' not in request.mimetype:     
            errorMIME = {"Error": "Unsupported Media Type"} 
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 415
            return (res)
             
        # if the accepted mimetype isnt json we return 406
        if 'application/json' not in request.accept_mimetypes:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)
             
        trueParkingSpot = json.loads(trueParkingSpot)
        if trueParkingSpot["boat"] != "Empty":
            errorMIME = {"Error": "Parking Spot isn't empty"} 
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return (res)

        
        assignParkingSpot(content["boatID"], content["parkingSpotID"])
        return("", 204)


    # run if other request method is called
    else:
        errorMethod = {"error": "Method Not Allowed"}
        res = make_response(json.dumps(errorMethod))
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 405
        return res


# takes post request wtih
#   {
#    "boatID": boatDataStoreID
#    "parkingSpotID": parkingSpotDataStoreID
#    }
@app.route('/removeParkingSpot', methods=['PATCH','PUT','DELETE','GET', 'POST'])
def removeSpot_patch():
    if request.method == 'DELETE':

        # load request object
        try:
            content = request.get_json()
        except:
            errorEmptyJson = {"Error": "Bad Request"}
            res = make_response(json.dumps(errorEmptyJson))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 400
            return res

        # if boat with this ID doesn't exist return this
        trueBoat = getBoat(content["boatID"])
        if trueBoat == False:
            errorNoBoat = {"Error": "No boat with this boat_id exists"}
            res = make_response(json.dumps(errorNoBoat))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        # if parkingSpot with this ID doesn't exist return this
        trueParkingSpot = getParkingSpot(content["parkingSpotID"])
        if trueParkingSpot == False:
            errorNoParkingSpot = {"Error": "No ParkingSpot with this ParkingSpot_id exists"}
            res = make_response(json.dumps(errorNoParkingSpot))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 404
            return res

        # if the mimetype isnt json, we return unsupported type 415
        if 'application/json' not in request.mimetype:     
            errorMIME = {"Error": "Unsupported Media Type"} 
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 415
            return (res)
             
        # if the accepted mimetype isnt json we return 406
        if 'application/json' not in request.accept_mimetypes:
            errorMIME = {"Error": "Not Acceptable"}
            res = make_response(json.dumps(errorMIME))
            res.headers['Content-Type'] = 'application/json'
            res.status_code = 406
            return (res)
             
        editBoat(content["boatID"], {"location": "At Sea"})
        editParkingSpot(content["parkingSpotID"], {"boat": "Empty"})
        
        return("", 204)


    # run if other request method is called
    else:
        errorMethod = {"error": "Method Not Allowed"}
        res = make_response(json.dumps(errorMethod))
        res.headers['Content-Type'] = 'application/json'
        res.status_code = 405
        return res


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():

    try:
        payload = verify_jwt(request)
        # print(payload["sub"])
    except:
        return (jsonify({"error": "Missing or invalid JWT"}), 401)

    return (payload, 200)          
        

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
