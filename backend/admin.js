const fs = require("fs");
const common = require("./common");
const auth = require("./auth");
const returnObject = common.returnObject;
const loadUserFile = common.loadUserFile;
const returnResponse = common.returnResponse;
const returnResponseExtra = common.returnResponseExtra;

function completeDeauth(socket, json) {
    var token = json.token;
    if (token == null) {
        returnResponse(socket, 46, 255, "Token not present");
    } else {
        var username = auth.tokens[token];
        if (username == null) {
            returnResponse(socket, 46, 239, "Bad token");
        } else {
            var userFile = loadUserFile(username);
            if (userFile.error == null) {
                var user = userFile.json;
                if (user.admin == null) {
                    returnResponse(socket, 46, 4, "Malformed userfile");
                } else {
                    if (user.admin == false) {
                        returnResponse(socket, 46, 40, "User is not admin");
                        console.log("CMDFAIL (N.A.) " + username);
                    } else {
                        var target = json.target;
                        if (target == null) {
                            returnResponse(socket, 46, 255, "Target not present");
                        } else {
                            var deauthCount = 0;
                            for (const [key, value] of Object.entries(auth.tokens)) {
                                if (value == target) {
                                    auth.tokens[key] = null;
                                    deauthCount++;
                                }
                            }
                            console.log("ADMDEATH " + username + " - " + target + " (" + deauthCount + ")")
                            returnResponseExtra(socket, 47, 34, "Good admin deauth", {"count": deauthCount});
                        }
                    }
                }
            } else if (userFile.error == "Nonexistant") {
                returnResponse(socket, 46, 3, "Nonexistant user");
            } else {
                returnResponse(socket, 46, 4, "Malformed userfile");
                console.error(userFile.error);
            }
        }
    }
}

function nonexistant(socket, json) {
    returnResponse(socket, 46, 254, "Nonexistant or protected type");
}

module.exports = {nonexistant, completeDeauth};