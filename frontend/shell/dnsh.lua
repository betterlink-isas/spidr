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
else
  error("You must use either the config flag or the bind argument")
end

if address == "" then
  error("You must set a bind address!")
elseif port == 0 or port == nil then
  error("You must set a bind port!")
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
      term.write("\n")
    else
      user = user:sub(0, #user-1)
      term.write("Password: ")
      local pass = term.read({pwchar="*"})
      if pass == false or user == nil then
        term.write("\n")
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

function change(newPass)
  socket:write(json.encode({["type"]=2,["token"]=token,["newPassword"]=newPass}))
  local data = json.decode(socket:read())
  if data.type == 14 then
    if data.status == 255 then
      if data.detail then
        print("Error 255: " .. data.detail)
      else
        print("Error 255: unknown")
      end
    elseif data.status == 6 then
      print("Error 6: Malformed password hash")
    elseif data.status == 239 then
      print("Bad token. Please try to deauth then auth again.")
    elseif data.status == 4 then
      print("Error 4: Malformed userfile")
    elseif data.status == 7 then
      print("Error 7: Could not write to userfile")
    elseif data.status == 3 then
      print("Error 3: Nonexistant user")
    else
      print("Undefined error")
    end
  elseif data.type == 15 then
    if data.status == 2 then
      print("Successfully changed password.")
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
end

function domains()
  socket:write(json.encode({["type"]=16,["token"]=token}))
  local data = json.decode(socket:read())
  if data.type == 30 then
    if data.status == 255 then
      if data.detail then
        print("Error 255: " .. data.detail)
      else
        print("Error 255: unknown")
      end
    elseif data.status == 239 then
      print("Bad token. Please try to deauth then auth again.")
    elseif data.status == 4 then
      print("Error 20: Malformed userfile")
    elseif data.status == 3 then
      print("Error 19: Nonexistant user")
    else
      print("Undefined error")
    end
  elseif data.type == 31 then
    if data.status == 16 then
      if data.extra.domains then
        print("Domains:")
        for _,v in ipairs(data.extra.domains) do
          print(v)
        end
      else
        print("Error: good response but no list")
      end
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
end

function adminDeauth(target)
  socket:write(json.encode({["type"]=34,["token"]=token,["target"]=target}))
  local data = json.decode(socket:read())
  if data.type == 46 then
    if data.status == 255 then
      if data.detail then
        print("Error 255: " .. data.detail)
      else
        print("Error 255: unknown")
      end
    elseif data.status == 239 then
      print("Bad token. Please try to deauth then auth again.")
    elseif data.status == 4 then
      print("Error 20: Malformed userfile")
    elseif data.status == 3 then
      print("Error 19: Nonexistant user")
    elseif data.status == 40 then
      print("Error: you are not a registered administrator!")
    else
      print("Undefined error")
    end
  elseif data.type == 47 then
    if data.status == 34 then
      if data.extra.count then
        print(string.format("Successfully deauthed %d tokens of user '%s'", data.extra.count, target))
      else
        print("Error: good response but no count")
      end
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
end

function passwdAsk()
  if token ~= "noauth" then
    term.write("New password: ")
    local pass = term.read({pwchar="*"})
    if pass == nil or pass == false then
      term.write("\n")
    else
      pass = pass:sub(0, #pass-1)
      term.write("\nConfirm new password: ")
      local confirm = term.read({pwchar="*"})
      if confirm == nil or confirm == false then
        term.write("\n")
      else
        term.write("\n")
        confirm = confirm:sub(0, #confirm-1)
        if confirm == pass then
          hash = strtohex(datacard.sha256(confirm))
          change(hash)
        else
          print("Passwords do not match! Please try again.")
        end
      end
    end
  else
    print("You are not authenticated!")
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
  elseif command == "gethash" then
    term.write("Password: ")
    local pass = term.read({pwchar="*"})
    if pass == false or pass == nil then
      term.write("\n")
    else
      pass = pass:sub(0, #pass-1)
      print("\nHash: ", strtohex(datacard.sha256(pass)))
    end
  elseif command == "passwd" then
    passwdAsk()
  elseif command == "domains" then
    if token ~= "noauth" then
      domains()
    else
      print("You are not authorized!")
    end
  elseif command == "admdeauth" then
    if token ~= "noauth" then
      if #args == 1 then
        print("Usage: admdeauth [username of user]")
      else
        adminDeauth(args[2])
      end
    else
      print("You are not authorized!")
    end
  elseif command == "help" then
    if #args == 1 then
      print("Commands: auth, deauth, token, exit, help, gethash, passwd, domains, admdeauth")
    else
      local comm = args[2]
      if comm == "auth" then
        print("auth: authenticates you")
      elseif comm == "deauth" then
        print("deauth: deauthenticates you but does not exist")
      elseif comm == "token" then
        print("token: prints your current authentication token")
      elseif comm == "exit" then
        print("exit: deauths and exists (same effect as ^D and ^C)")
      elseif comm == "help" then
        print("help [command]: shows help messages for commands, lists commands with no arguments")
      elseif comm == "gethash" then
        print("gethash: gets the SHA256 hash for a password")
      elseif comm == "passwd" then
        print("passwd: changes your password (will prompt for new password)")
      elseif comm == "domains" then
        print("domains: lists what domains you have authority over")
      elseif comm == "admdeauth" then
        print("admdeauth [username]: deauths all logged in instances of a user (admin only)")
      else
        print("help: invalid command")
      end
    end
  else
    print("dnsh: command '" .. command .. "' is not valid")
  end
end
if token ~= "noauth" then
  deauth()
end
socket:close()