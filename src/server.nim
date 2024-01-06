## This program implement a server
## that load md5 hashes from a file and send them to client
## if they succeed to break the hash (the server verifies) it will print it
## otherwise it will show a ":("

import std/[
    os,
    net,
    strformat, strutils, sequtils,
    logging
]
import checksums/md5
import colored_logger

proc checkMD5*(password, hash: string): bool {.inline.} = getMD5(password) == hash
    ## do the md5sum of `password` and compare to `hash`

proc handle*(client: Socket, hash: string): bool =
    ## get the hash from the server and try to break it
    ## send the password if found or "nope"
    defer: close(client)
    client.send(hash & "\n")
    info(&"Sent {repr hash} to client")
    let password = client.recvLine()
    info(&"Got {repr password} from client")
    if checkMD5(password, hash):
        info(&"{hash}  {password}")
        return true
    info(&"{repr password} doesnt match the hash :(")
    return false

proc main() =
    if paramCount() != 3: quit &"usage: {paramStr(0)} [ip] [port] [file]"
    
    let
        ip       = paramStr(1)
        port     = try: parseUInt(paramStr(2)) except: quit "wrong port format"
    var
        hashes   = try: paramStr(3).lines.toSeq() except: quit "couldnt open the file"
        server   = newSocket()

    addHandler(newColoredLogger())
    info(&"Loaded {hashes.len} md5 hash")
    setSockOpt(server, OptReuseAddr, true)
    try: bindAddr(server, Port(port), ip) except: quit "couldnt bind the address"
    listen(server, 32)
    info(&"Listening on {getLocalAddr server}")

    while hashes.len > 0:
        var hash = hashes[hashes.len-1]
        info(&"Loaded {repr hash} waiting for a client")
        var client: Socket
        try: accept(server, client) except: (warn("Failed to accept client"); continue)
        info(&"New Client on {getPeerAddr client}")
        if handle(client, hash):
            discard pop(hashes)
    info(&"no more hash to crack, bye :)")

main()
