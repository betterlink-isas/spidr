local component = require("component")
local data = component.data
local term = require("term")

function strtohex(str)
    checkArg(1, str, "string")
    local hex = ""
    for i=1,#str do
        local byte = string.byte(str, i)
        hex = hex .. string.format("%02x", byte)
    end
    return hex
end

local pass = term.read({pwchar = "*"})
if pass == false or pass == nil then
  os.exit(0)
end
pass = pass:sub(0, #pass-1)

print(strtohex(data.sha256(pass)))