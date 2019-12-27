#!/bin/env node
const net = require("net");
const fs = require("fs");
const auth = require("./auth");
const domain = require("./domain");
const common = require("./common");
const admin = require("./admin");
const returnObject = common.returnObject;
const returnResponse = common.returnResponse;
const returnResponseExtra = common.returnResponseExtra;
const yargs = require ("yargs");
const uuidv4 = require('uuid/v4');

const argv = yargs(process.argv)
    .option('port', {
        alias: 'p',
        description: 'The port to listen on',
        type: 'number',
        default: 8053
    }).option('address', {
        alias: 'a',
        description: 'The address to listen on',
        type: 'string',
        default: '127.0.0.1'
    })
    .help()
    .alias('help', 'h')
    .argv;

console.log("DNS Proto Backend v1.0.0+git");

var server = new net.createServer(function(socket) {
    socket.setNoDelay(true);
    returnResponse(socket, 240, 208, "Connected");
    socket.on('data', function(data) {
        try {
            const json = JSON.parse(data);
            if (json.type == 0) {
                auth.auth(socket, json);
            } else if (json.type == 1) {
                auth.deauth(socket, json);
            } else if (json.type == 2) {
                auth.change(socket, json);
            } else if (json.type >= 3 && json.type <= 15) {
                auth.nonexistant(socket, json);
            } else if (json.type == 16) {
                domain.list(socket, json);
            } else if (json.type >= 17 && json.type <= 31) {
                domain.nonexistant(socket, json);
            } else if (json.type == 32) {

            } else if (json.type == 33) {

            } else if (json.type == 34) {
                admin.completeDeauth(socket, json);
            } else if (json.type == 35) {
                
            } else if (json.type == 36) {

            } else if (json.type == 37) {
                
            } else if (json.type == 38) {

            } else if (json.type == 39) {

            } else if (json.type >= 40 && json.type <= 47) {
                admin.nonexistant(socket, json);
            } else if (json.type == null) {
                returnObject(socket, {"type": 254, "status": 252, "detail": "Type not present"});
            }
        } catch (err) {
            returnObject(socket, {"type": 254, "status": 253, "detail": err.toString()});
        }
    });
    socket.on('close', function() {});
});

server.listen(argv.port, argv.address);
console.log("Now listening on " + argv.address + ":" + argv.port);