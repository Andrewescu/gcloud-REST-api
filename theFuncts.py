from google.cloud import datastore
import json


client = datastore.Client()

acceptedChars = set("abcdefghijklmnopqrstuvwxyz -,0123456789") 


### BEGIN USER FUNCTIONS


# Needs try-except block to catch missing parameters, that's only possible error
def addUser(name, sub):
    newUser = datastore.entity.Entity(key=client.key("User"))
    client.put(newUser)
    newUser.update({"name": name, "uniqueID": sub})
    client.put(newUser)
    responseUser = {
        "name": name,
        "uniqueID": sub,
        "id": newUser.key.id
    }
    return (json.dumps(responseUser))


def getAllUsers():
    query = client.query(kind="User")
    results = list(query.fetch())
    for e in results:
        e["id"] = e.key.id
    return json.dumps(results)


def uniqueUserID(uniqueID):
    allUsers = json.loads(getAllUsers())
    for User in allUsers:
        if User["uniqueID"] == uniqueID:
            return(False)
    return (True)


### END USER FUNCTIONS
### BEGIN BOAT FUNCTIONS

# Needs try-except block to catch missing parameters, that's only possible error
# uniqueID is sub value in user's JWT
def addBoat(name, boatType, length, uniqueID, baseURL):
    newBoat = datastore.entity.Entity(key=client.key("boat"))
    client.put(newBoat)
    selfLink = str(baseURL) + "/" + str(newBoat.key.id)
    newBoat.update({"name": name, "boatType": boatType,
        "length": length, "location": "At Sea", "uniqueID": uniqueID, "self": selfLink})
    client.put(newBoat)

    responseBoat = {
        "name": name,
        "boatType": boatType,
        "length": length,
        "location": "At Sea",
        "uniqueID": uniqueID,
        "self": selfLink,
        "id": newBoat.key.id
    }
    
    return (json.dumps(responseBoat))


# Returns false if boatId doesn't exist
def getBoat(boatId):
    boatKey = client.key("boat", int(boatId))
    boat = client.get(key=boatKey)
    if (boat == None):
        return False
    boat["id"] = boat.key.id
    return json.dumps(boat)


def deleteBoat(boatId):
    boatReal = getBoat(boatId)
    if (boatReal == False):
        return False
    key = client.key("boat", int(boatId))
    client.delete(key)
    return True


# Requires try-except block to catch missing parameters
# returns false if boatId doesn't exist
def editBoat(boatId, content): # type, length
    boatKey = client.key("boat", int(boatId))
    boat = client.get(key=boatKey)
    if (boat == None):
        return False
    boatDiction = {}
    for entry in content:
        boatDiction[entry] = content[entry]
    boat.update(boatDiction)
    client.put(boat)
    return (getBoat(boatId))


def getAllBoats():
    query = client.query(kind="boat")
    results = list(query.fetch())
    for e in results:
        e["id"] = e.key.id
    return json.dumps(results)


###  END BOAT FUNCTIONS



### BEGIN PARKINGSPOT FUNCTIONS

# Needs try-except block to catch missing parameters, that's only possible error
# uniqueID is sub value in user's JWT
def addParkingSpot(name, address, cost, baseURL):
    newParkingSpot = datastore.entity.Entity(key=client.key("parkingSpot"))
    client.put(newParkingSpot)
    selfLink = str(baseURL) + "/" + str(newParkingSpot.key.id)
    newParkingSpot.update({"name": name, "address": address,
        "cost": cost, "boat": "Empty", "self": selfLink})
    client.put(newParkingSpot)

    responseParkingSpot = {
        "name": name,
        "address": address,
        "cost": cost,
        "boat": "Empty",
        "self": selfLink,
        "id": newParkingSpot.key.id
    }
    
    return (json.dumps(responseParkingSpot))


# Returns false if parkingSpotId doesn't exist
def getParkingSpot(parkingSpotId):
    parkingSpotKey = client.key("parkingSpot", int(parkingSpotId))
    parkingSpot = client.get(key=parkingSpotKey)
    if (parkingSpot == None):
        return False
    parkingSpot["id"] = parkingSpot.key.id
    return json.dumps(parkingSpot)


def deleteParkingSpot(parkingSpotId):
    parkingSpotReal = getParkingSpot(parkingSpotId)
    if (parkingSpotReal == False):
        return False
    key = client.key("parkingSpot", int(parkingSpotId))
    client.delete(key)
    return True


# Requires try-except block to catch missing parameters
# returns false if parkingSpotId doesn't exist
def editParkingSpot(parkingSpotId, content): # type, length
    parkingSpotKey = client.key("parkingSpot", int(parkingSpotId))
    parkingSpot = client.get(key=parkingSpotKey)
    if (parkingSpot == None):
        return False
    parkingSpotDiction = {}
    for entry in content:
        parkingSpotDiction[entry] = content[entry]
    parkingSpot.update(parkingSpotDiction)
    client.put(parkingSpot)
    return (getParkingSpot(parkingSpotId))


def getAllParkingSpots():
    query = client.query(kind="parkingSpot")
    results = list(query.fetch())
    for e in results:
        e["id"] = e.key.id
    return json.dumps(results)


### END PARKINGSPOT FUNCTIONS


def verifyaddress(content):
    parkingSpotaddress = content["address"]
    

    if isinstance(parkingSpotaddress, str) == False:
        return ("address must be a string")
    
    length = len(parkingSpotaddress) 

    if parkingSpotaddress == "" or len(parkingSpotaddress) == 0:
        return ("address cannot be empty")

    if length > 27:
        return ("address exceeded maximum characters")

    if parkingSpotaddress[0] == " " or parkingSpotaddress[length - 1] == " ":
        return ("address cannot begin or end with whitespace")

    if "\n" in parkingSpotaddress:
        return ("address cannot contain newline character")
    
    if "  " in parkingSpotaddress:
        return("address cannot contain consequtive whitespace")

    if "--" in parkingSpotaddress:
        return("address cannot contain consequtive dashes")    

    parkingSpotaddressLower = parkingSpotaddress.lower()
    for char in parkingSpotaddressLower:
        if char not in acceptedChars:
            return("address contains unaccepted character(s)")
    return(0)


def verifyCost(content):
    parkingSpotCost = content["cost"]
    if isinstance(parkingSpotCost, int) == False:
        return ("Cost must be an integer")

    if parkingSpotCost < 0:
        return ("parkingSpotCost must be greater than or equal to 0")
    return(0)


def uniqueParkingSpotAddress(address):
    allParkingSpots = json.loads(getAllParkingSpots())
    for parkingSpot in allParkingSpots:
        if parkingSpot["address"] == address:
            return("parkingSpot address already exists in database")
    return (0)


def verifyName(content):
    boatName = content["name"]
    

    if isinstance(boatName, str) == False:
        return ("Name must be a string")
    
    length = len(boatName) 

    if boatName == "" or len(boatName) == 0:
        return ("Name cannot be empty")

    if length > 27:
        return ("Name exceeded maximum characters")

    if boatName[0] == " " or boatName[length - 1] == " ":
        return ("Name cannot begin or end with whitespace")

    if "\n" in boatName:
        return ("Name cannot contain newline character")
    
    if "  " in boatName:
        return("Name cannot contain consequtive whitespace")

    if "--" in boatName:
        return("Name cannot contain consequtive dashes")    

    boatNameLower = boatName.lower()
    for char in boatNameLower:
        if char not in acceptedChars:
            return("Name contains unaccepted character(s)")
    return(0)

    
def verifyType(content):
    boatType = content["boatType"]

    if isinstance(boatType, str) == False:
        return ("Type must be a string")

    length = len(boatType) 
    
    if boatType == "" or len(boatType) == 0:
        return ("Type cannot be empty")

    if length > 27:
        return ("Type exceeded maximum characters")

    if boatType[0] == " " or boatType[length - 1] == " ":
        return ("Type cannot begin or end with whitespace")

    if "\n" in boatType:
        return ("Type cannot contain newline character")
    
    if "  " in boatType:
        return("Type cannot contain consequtive whitespace")

    if "--" in boatType:
        return("Type cannot contain consequtive dashes")    

    boatTypeLower = boatType.lower()
    for char in boatTypeLower:
        if char not in acceptedChars:
            return("Type contains unaccepted character(s)")
    return(0)
 

def verifyLength(content):
    boatLength = content["length"]
    if isinstance(boatLength, int) == False:
        return ("Length must be an integer")

    if boatLength < 1:
        return ("Length must be greater than 0")
    return(0)


def uniqueBoatName(name):
    allBoats = json.loads(getAllBoats())
    for boat in allBoats:
        if boat["name"] == name:
            return("Boat name already exists in database")
    return (0)


def uniqueParkingSpotName(name):
    allParkingSpots = json.loads(getAllParkingSpots())
    for parkingSpot in allParkingSpots:
        if parkingSpot["name"] == name:
            return("parkingSpot name already exists in database")
    return (0)


def assignParkingSpot(boatID, parkingSpotID):
    theBoat = json.loads(getBoat(boatID))
    theParkingSpot = json.loads(getParkingSpot(parkingSpotID))
    # "location": "At Sea"
    if (theBoat["location"] != "At Sea"):
        editParkingSpot(theBoat["location"], {"boat": "Empty"})

    editParkingSpot(parkingSpotID, {"boat": boatID})
    editBoat(boatID, {"location": parkingSpotID})
    return
