# DNS Proto

A DNS-like protocol thingy for OpenComputers

It uses a NodeJS TCP backend and has an interface accessible through TCP via Lua or any other means

It will be used in combination with a TCP-based relay which proxies information from one computer to another through that same server (not the same backend/port though) to allow communication between two computers without needing either a bunch of wireless network relays or linked cards.

Each computer is assigned an IP address using UUIDv4. That IP can be linked to DNS through this protocol and can allow you to go to `example.com` instead of something like `e046e1f6-2f67-440b-9c6e-2f9c9e677d68`.
