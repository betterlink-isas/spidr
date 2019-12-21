local component = require("component")
local term = require("term")
local json = require("json")
local event = require("event")
local shell = require("shell")

local incard = component.internet
local internet = require("internet")
local data = component.data
print("DNS Proto Shell (v1.0.0+git)")
local args,ops = shell.parse(...)
if ops.h or ops.help then
  print("Usage: dpsh [-h|--help] [-p|--printHash]")
  os.exit(0)
end
term.write("Username: ")
local user = term.read()
if user == false or user == nil then
  os.exit(0)
end
user = user:sub(0, #user-1)
term.write("Password: ")
local pass = term.read({pwchar = "*"})
if pass == false or pass == nil then
  os.exit(0)
end
pass = pass:sub(0, #pass-1)
function strtohex(str)
  checkArg(1, str, "string")
  local hex = ""
  for i=1,#str do
    local byte = string.byte(str, i)
    hex = hex .. string.format("%02x", byte)
  end
  return hex
end
local hash = strtohex(data.sha256(pass))
term.write("\n")

local authRequest = {
  ["type"] = "AUTH REQUEST",
  ["username"] = user,
  ["password"] = hash
}

if ops.p or ops.printHash then
  print("Hash: " .. hash)
  os.exit(0)
end
local socket = internet.open("68.102.163.235", 8053)
if (socket) then
else
  error("Could not connect to server")
end
socket:setTimeout(5)
socket:setvbuf("no")
socket:write(json.encode(authRequest))
local data = json.decode(socket:read("*l"))
local token = ""
if data.type == "AUTH RESPONSE" then
  if data.status == "BAD AUTH" then
    error("Bad authentication or credentials")
  elseif data.status == "GOOD AUTH" then
    if data.token then
      print("Successfully authenticated")
      token = data.token
    else
      error("Invalid response from server")
    end
  else
    error("Invalid response from server")
  end
elseif data.type == "ERROR" then
  if data.error then
    error(data.error)
  else
    error("Invalid response from server")
  end
else
  error("Invalid response from server")
end

function splitBySpaces(string)
  chunks = {}
  for substring in string:gmatch("%S+") do
    table.insert(chunks, substring)
  end
  return chunks
end

hist = {}
while true do
  term.write("dpsh$ ")
  local command = term.read(hist)
  if command == false or command == nil or command == "exit\n" or command == "logout\n" then
    break
  end
  command = command:sub(0, #command-1)
  command = command:lower()
  hist[#hist+1] = command
  args = splitBySpaces(command)
  command = args[1]
  if command == "ls" or command == "list" then
    socket:write(json.encode({["type"]="DOMAIN LIST",["token"]=token}))
    local data = json.decode(socket:read("*l"))
    if data.type == "DOMAIN RESPONSE" then
      if data.status == "BAD USERFILE" then
        print("Bad user file, please contact administrator")
      elseif data.status == "BAD TOKEN" then
        print("Bad token, please reauth and try again (close and reopen dpsh)")
      elseif data.status == "GOOD LIST" then
        if data.list then
          for _,v in ipairs(data.list) do
            print(v)
          end
        else
          error("Invalid response from server")
        end
      else
        error("Invalid response from server")
      end
    elseif data.type == "ERROR" then
      if data.error then
        error(data.error)
      else
        error("Invalid response from server")
      end
    else
      error("Invalid response from server")
    end
  elseif command == "help" then
    if #args == 1 then
      print("Commands: help, ls|list, exit|logout")
    else
      comm = args[2]
      if comm == "list" or comm == "ls" then
        print("ls|list: lists all domains you have authority over")
      elseif comm == "exit" or comm == "logout" then
        print("exit|logout: deauths and closes the console. Same effect with ^D and ^C")
      else
        print("Invalid command!")
      end
    end
  else
    print("Invalid command!")
  end
end
socket:write(json.encode({
  ["type"] = "AUTH DEAUTH",
  ["token"] = token
}))
local data = json.decode(socket:read("*l"))
if data.type == "AUTH RESPONSE" then
  if data.status == "GOOD DEAUTH" then
    print("Successfully deauthenticated. Goodbye.")
  else
    error("Invalid response from server")
  end
elseif data.type == "ERROR" then
  if data.error then
    error(data.error)
  else
    error("Invalid response from server")
  end
else
  error("Invalid response from server")
end
socket:close()