const net = require("net");
const fs = require("fs");

function returnObject(socket, data) {
    socket.write(JSON.stringify(data) + "\n");
}

function returnResponse(socket, type, status, detail) {
    returnObject(socket, {"type": type, "status": status, "detail": detail})
}

function returnResponseExtra(socket, type, status, detail, extra) {
    returnObject(socket, {"type": type, "status": status, "detail": detail, "extra": extra});
}

function loadUserFile(user) {
    var path = "authorities/" + user + ".json";
    if (fs.existsSync(path)) {
        var data = fs.readFileSync(path);
        try {
            var userJson = JSON.parse(data);
            return {"error": null, "json": userJson};
        } catch (err) {
            console.error(err);
            return {"error": err, "json": null};
        }
    } else {
        return {"error": "Nonexistant", "json": null};
    }
}

module.exports = {returnObject, returnResponse, returnResponseExtra, loadUserFile};