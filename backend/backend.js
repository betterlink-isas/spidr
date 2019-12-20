var net = require("net");
var fs = require("fs");
const uuidv4 = require('uuid/v4');

function returnObject(socket, data) {
    socket.write(JSON.stringify(data) + "\n");
}

var tokens = {}

var server = new net.createServer(function(socket) {
    socket.setNoDelay(true);
    socket.on('data', function(data) {
        try {
            const json = JSON.parse(data);
            if (json.type == "AUTH REQUEST") {
                var user = json.username;
                var pass = json.password;
                if (user == null) {
                    returnObject(socket, {"type": "ERROR", "error": "Malformed request (username not present)"});
                } else if (pass == null) {
                    returnObject(socket, {"type": "ERROR", "error": "Malformed request (password not present)"});
                } else {
                    if (fs.existsSync('authorities/' + user + '.json')) {
                        var data = fs.readFileSync('authorities/' + user + '.json');
                        try {
                            var authority = JSON.parse(data);
                            if (authority.hash == pass) {
                                var uuid = uuidv4();
                                tokens[uuid] = user;
                                returnObject(socket, {
                                    "type": "AUTH RESPONSE",
                                    "status": "GOOD AUTH",
                                    "token": uuid
                                });
                                console.log("AUTH " + user);
                            }
                        } catch (err) {
                            console.error(err);
                            returnObject(socket, {
                                "type": "AUTH RESPONSE",
                                "status": "BAD AUTH"
                            });
                        }
                    } else {
                        returnObject(socket, {
                            "type": "AUTH RESPONSE",
                            "status": "BAD AUTH"
                        });
                    }
                }
            } else if (json.type == "AUTH DEAUTH") {
                var token = json.token;
                if (token == null) {
                    returnObject(socket, {"type": "ERROR", "error": "Malformed request (token not present)"});
                } else {
                    console.log("DEAUTH " + tokens[token]);
                    tokens[token] = null;
                }
                returnObject(socket, {"type": "AUTH RESPONSE", "status": "GOOD DEAUTH"})
            } else if (json.type == null) {
                returnObject(socket, {"type": "ERROR", "error": "Malformed request (type not present)"});
            }
        } catch (err) {
            returnObject(socket, {"type": "ERROR", "error": err.toString()});
        }
    });
});

server.listen(8053, '192.168.0.33');

