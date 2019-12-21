var net = require("net");
var fs = require("fs");
const uuidv4 = require('uuid/v4');

function returnObject(socket, data) {
    socket.write(JSON.stringify(data) + "\n");
}

var tokens = {}

var server = new net.createServer(function(socket) {
    //console.log("CONN " + socket.remoteAddress);
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
                            } else {
                                returnObject(socket, {
                                    "type": "AUTH RESPONSE",
                                    "status": "BAD AUTH"
                                });
                                console.log("FAIL AUTH (BC.) " + user);
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
                        console.log("FAIL AUTH (NE.) " + user);
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
            } else if (json.type == "DOMAIN LIST") {
                var token = json.token;
                if (token == null) {
                    returnObject(socket, {"type": "ERROR", "error": "Malformed request (token not present)"});
                } else {
                    if (fs.existsSync('authorities/' + tokens[token] + '.json')) {
                        var data = fs.readFileSync('authorities/' + tokens[token] + '.json');
                        try {
                            var user = JSON.parse(data);
                            var domains = user.domains;
                            if (domains == null) {
                                returnObject(socket, {
                                    "type": "DOMAIN RESPONSE",
                                    "status": "BAD USERFILE"
                                });
                            } else {
                                returnObject(socket, {
                                    "type": "DOMAIN RESPONSE",
                                    "status": "GOOD LIST",
                                    "list": domains
                                });
                            }
                        } catch (err) {
                            console.error(err);
                            returnObject(socket, {
                                "type": "DOMAIN RESPONSE",
                                "status": "BAD USERFILE"
                            });
                        }
                    } else {
                        returnObject(socket, {
                            "type": "DOMAIN RESPONSE",
                            "status": "BAD TOKEN"
                        });
                    }
                }
            } else if (json.type == null) {
                returnObject(socket, {"type": "ERROR", "error": "Malformed request (type not present)"});
            }
        } catch (err) {
            returnObject(socket, {"type": "ERROR", "error": err.toString()});
        }
    });
    socket.on('close', function() {
        //console.log("DECONN " + socket.remoteAddress);
    });
});

server.listen(8053, '192.168.0.33');

