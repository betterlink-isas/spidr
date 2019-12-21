const fs = require("fs");
const common = require("./common");
const returnObject = common.returnObject;
const loadUserFile = common.loadUserFile;
const returnResponse = common.returnResponse;
const returnResponseExtra = common.returnResponseExtra;
const uuidv4 = require("uuid/v4");


var tokens = {}

function auth(socket, json) {
    var username = json.username;
    var password = json.password;
    if (username == null) {
        returnResponse(socket, 14, 255, "Username not present");
    } else if (password == null) {
        returnResponse(socket, 14, 255, "Password not present");
    } else {
        var userFile = loadUserFile(username);
        if (userFile.error == null) {
            var user = userFile.json;
            if (user.hash == null) {
                returnResponse(socket, 14, 4, "Malformed userfile");
            } else {
                if (user.hash == password) {
                    var token = uuidv4();
                    tokens[token] = username;
                    returnResponseExtra(socket, 15, 0, "Good authentication", {"token": token});
                    console.log("AUTH " + username);
                } else {
                    returnResponse(socket, 14, 5, "Bad credentials");
                    console.log("AUTH FAIL (B.C.) " + username);
                }
            }
        } else if (userFile.error == "Nonexistant") {
            returnResponse(socket, 14, 3, "Nonexistant user");
            console.log("AUTH FAIL (N.E.) " + username);
        } else {
            returnResponse(socket, 14, 4, "Malformed userfile");
            console.error(userFile.error);
        }
    }
}

function deauth(socket, json) {
    var token = json.token;
    if (token == null) {
        returnResponse(socket, 14, 255, "Token not present");
    } else {
        console.log("DEAUTH " + tokens[token]);
        tokens[token] = null;
        returnResponse(socket, 15, 1, "Good deauthentication");
    }
}

function change(socket, json) {
    var token = json.token;
    var newPassword = json.newPassword;
    if (token == null) {
        returnResponse(socket, 14, 255, "Token not present");
    } else if (newPassword == null) {
        returnResponse(socket, 14, 255, "New password not present");
    } else if (!(/^([a-f0-9]{64})$/.test(newPassword))) {
        returnResponse(socket, 14, 6, "Malformed password hash");
    } else {
        var username = tokens[token];
        if (username == null) {
            returnResponse(socket, 14, 239, "Bad token");
        } else {
            var userFile = loadUserFile(username);
            if (userFile.error == null) {
                var user = userFile.json;
                if (user.hash == null) {
                    returnResponse(socket, 14, 4, "Malformed userfile");
                } else {
                    user.hash = newPassword;
                    var strjson = JSON.stringify(user);
                    try {
                        fs.writeFileSync('authorities/' + username + '.json', strjson);
                        returnResponse(socket, 15, 2, "Good change");
                        console.log("CHANGE PASS " + username);
                    } catch (err) {
                        returnResponse(socket, 14, 7, "Could not write to userfile");
                    }
                }
            } else if (userFile.error == "Nonexistant") {
                returnResponse(socket, 14, 3, "Nonexistant user");
            } else {
                returnResponse(socket, 14, 4, "Malformed userfile");
                console.error(userFile.error);
            }
        }
    }
}

function nonexistant(socket, json) {
    returnResponse(socket, 14, 254, "Nonexistant or protected type");
}

module.exports = {auth, deauth, change, tokens, nonexistant};