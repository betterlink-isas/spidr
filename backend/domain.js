const fs = require("fs");
const common = require("./common");
const auth = require("./auth");
const returnObject = common.returnObject;
const loadUserFile = common.loadUserFile;
const returnResponse = common.returnResponse;
const returnResponseExtra = common.returnResponseExtra;

function list(socket, json) {
    var token = json.token;
    if (token == null) {
        returnResponse(socket, 30, 255, "Token not present");
    } else {
        var username = auth.tokens[token];
        if (username == null) {
            returnResponse(socket, 30, 239, "Bad token");
        } else {
            var userFile = loadUserFile(username);
            if (userFile.error == null) {
                var user = userFile.json;
                if (user.domains == null) {
                    returnResponse(socket, 30, 4, "Malformed userfile");
                } else {
                    returnResponseExtra(socket, 31, 16, "Good list", {"domains": user.domains});
                }
            } else if (userFile.error == "Nonexistant") {
                returnResponse(socket, 30, 3, "Nonexistant user");
            } else {
                returnResponse(socket, 30, 4, "Malformed userfile");
                console.error(userFile.error);
            }
        }
    }
}

function nonexistant(socket, json) {
    returnResponse(socket, 30, 254, "Nonexistant or protected type");
}

module.exports = {list, nonexistant};