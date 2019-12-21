local component = require("component")
local term = require("term")
local json = require("json")
local event = require("event")
local shell = require("shell")
local internet = require("internet")
local argparse = require("argparse")
local fs = require("filesystem")
local serial = require("serialization")
local datacard = component.data

print("DNShell v1.0.0+git")

local parser = argparse()
                :name("dnsh")
                :description("DNShell (An interactive shell for interacting with a DNS Proto server.)")
                :epilog("For more info, see https://github.com/teamisotope/dns-proto-dev")

parser:mutex(
  parser:argument("bind", "Address/port to connect to (format: 'address:port')")
        :args("?"),
  parser:flag("-c --config", "Whether or not to use the config file (/usr/share/dnsh.config)")
)

function e(code)
  os.exit(code)
end


local args = parser:parse({...})

address = ""
port = 0

if args.bind then
    local addr, portRaw = args.bind:match("([0-9.A-Za-z_-]+):([0-9]+)")
    address = addr
    port = tonumber(portRaw)
elseif args.config then
  if fs.exists("/usr/share/dnsh.config") then
    file = io.open("/usr/share/dnsh.config", "r")
    if file then
      configRaw = file:read("*a")
      config = serial.unserialize(configRaw)
      if not config.address then
        error("Config does not contain address")
      elseif not config.port then
        error("Config does not contain port")
      else
        address = config.address
        port = config.port
      end
    else
      error("Could not open config file!")
    end
  else
    error("Config file does not exist!")
  end
end

local socket = internet.open(address, port)
if not socket then
  print("Could not connect to server")
  e(-1)
end
socket:setTimeout(5)
socket:setvbuf("no")
local data = json.decode(socket:read())
if data.type == 240 then
  if data.status == 208 then
    print("Ready!")
  else
    print("Invalid ready packet from server")
    e(-1)
  end
else
  print("Invalid ready packet from server")
  e(-1)
end

function splitBySpaces(str)
  chunks = {}
  for substring in str:gmatch("%S+") do
    table.insert(chunks, substring)
  end
  return chunks
end

function strtohex(str)
  checkArg(1, str, "string")
  local hex = ""
  for i=1,#str do
    local byte = string.byte(str, i)
    hex = hex .. string.format("%02x", byte)
  end
  return hex
end

username = "noauth"
history = {}
token = "noauth"

function deauth()
  if token ~= "noauth" then
    socket:write(json.encode({["type"]=1,["token"]=token}))
    local data = json.decode(socket:read())
    if data.type == 14 then
      if data.status == 255 then
        if data.detail then
          print("Error 255: " .. data.detail)
        else
          print("Error 255: unknown")
        end
      else
        print("Unknown error.")
      end
    elseif data.type == 15 then
      if data.status == 1 then
        print("Successfully deauthenticated.")
        username = "noauth"
        token = "noauth"
      else
        print("Error: good response but bad status")
      end
    elseif data.type == 254 then
      if data.status == 253 then
        if data.detail then
          print("Invalid request JSON: " .. data.detail)
        else
          print("Invalid request JSON (unknown)")
        end
      elseif data.status == 252 then
        print("Error 252: Type not present")
      else
        print("General unknown error")
      end
    else
      print("Invalid response from server")
    end
  else
    print("Not authenticated, deauth not necessary.")
  end
end

function auth(user, pass)
  socket:write(json.encode({["type"]=0,["username"]=user,["password"]=pass}))
  local data = json.decode(socket:read())
    if data.type == 14 then
      if data.status == 255 then
        if data.detail then
          print("Error 255: " .. data.detail)
        else
          print("Error 255 (undefined)")
        end
      elseif data.status == 3 then
        print("User '" .. user .. "' does not exist!")
      elseif data.status == 4 then
        print("Error 4: Malformed userfile.")
      elseif data.status == 5 then
        print("Bad credentials.")
      elseif data.status == 254 then
        print("Error 254: Nonexistant or protected type")
      else
        print("Undefined error")
      end
    elseif data.type == 15 then
      if data.status == 0 then
        if data.extra.token then
          print("Successfully authenticated.")
          username = user
          token = data.extra.token
        else
           print("Error: good authentication but no token")
        end
      else
        print("Error: Good response but bad status")
      end
    elseif data.type == 254 then
      if data.status == 252 then
        print("Error 252: unspecified type")
      elseif data.status == 253 then
        if data.detail then
          print("Error 253: invalid request JSON (" .. data.detail .. ")")
        else
          print("Error 253: invalid request JSON")
        end
      else
        print("General unknown error.")
      end
    else
      print("Invalid response from server")
    end
end

function authAsk()
  if username == "noauth" then
    io.write("Username: ")
    local user = term.read()
    if user == false or user == nil then
      term.write("^C\n")
    else
      user = user:sub(0, #user-1)
      term.write("Password: ")
      local pass = term.read({pwchar="*"})
      if pass == false or user == nil then
        term.write("^C\n")
      else
        pass = pass:sub(0, #pass-1)
        hash = strtohex(datacard.sha256(pass))
        term.write("\n")
        auth(user, hash)
      end
    end
  else
    print("You are already authenticated!")
  end
end

while true do
  term.write(username .. "@dnsh# ")
  local command = term.read(history)
  if command == false or command == nil then
    break
  end
  command = command:sub(0, #command-1)
  history[#history+1] = command
  args = splitBySpaces(command)
  command = args[1]
  command = command:lower()
  if command == "auth" then
    authAsk()
  elseif command == "deauth" then
    deauth()
  elseif command == "token" then
    if token == "noauth" then
      print("Not authenticated.")
    else 
      print(token)
    end
  elseif command == "exit" then
    break
  end
end
if token ~= "noauth" then
  deauth()
end
socket:close()