// This is an example document for authentication
// client -> server
var cts = {
    "type": "AUTH REQUEST",
    "username": "paradox",
    "password": "332d9f45d3304afe2f368dcfa35fe7a1372372f69b8120ce8b1331b94595aa69"
};
// server -> client
// bad auth
var stcb = {
    "type": "AUTH RESPONSE",
    "status": "BAD AUTH"
};
// good auth
var stcg = {
    "type": "AUTH RESPONSE",
    "status": "GOOD AUTH",
    "token": "172888e3-52c4-4509-8a67-f96e09eb34e6"
}