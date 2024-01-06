## This program implement a client
## that receives a md5 hash and try to break it
## if it succeed it will send back the password
## otherwise it will send "nope"

import std/[
    os,
    net,
    strformat, strutils, sequtils,
    logging, times
]
import checksums/md5
import colored_logger

const
    BRUTE_FORCE_LEN* = 5 ## \
        ## length of generated password
    CHARSET*         = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ## \
        ## charset to use to generate password

proc checkMD5*(password, hash: string): bool {.inline.} = getMD5(password) == hash
    ## do the md5sum of `password` and compare to `hash`

proc raw_force*(str: var string, hash: string, str_pos: uint): string =
    ## recursive function that generates password of length `BRUTE_FORCE_LEN`
    ## using `CHARSET` and for each generated password of the correct length
    ## check if the md5sum match `hash`
    if str_pos == BRUTE_FORCE_LEN:
        if checkMD5(str, hash):
            info(&"{repr hash}  {repr str}")
            return str
        return ""
    for i in 0..CHARSET.len-1:
        str[str_pos] = CHARSET[i]
        if raw_force(str, hash, str_pos+1).len == BRUTE_FORCE_LEN:
            return str
    return "nope"

proc crack*(hash: string, wordlist: seq[string]): string =
    ## try to crack the `hash` using `wordlist` first
    ##
    ## if it didnt succeed, try raw brute force generating
    ## password using `CHARSET` of length `BRUTE_FORCE_LEN`
    info(&"Trying to crack {repr hash}")
    for word in wordlist:
        debug(&"Trying with {repr word}")
        if checkMD5(word, hash):
            info(&"{repr word} match {repr hash}")
            return word
    warn(&"Couldnt find matching password for {repr hash}")
    info(&"Trying raw brute force with max length {repr BRUTE_FORCE_LEN}")
    var tmp = newString(BRUTE_FORCE_LEN)
    return raw_force(tmp, hash, 0.uint)

proc handle*(server: Socket, wordlist: seq[string]) =
    ## get the hash from the server and try to break it
    ## send the password if found or "nope"
    defer: close(server)
    let
        hash     = recvLine(server)
        password = crack(hash, wordlist)
    server.send(password & "\n")

proc main() =
    if paramCount() != 3: quit &"usage: {paramStr(0)} [ip] [port] [file]"
    
    let
        ip       = paramStr(1)
        port     = try: parseUInt(paramStr(2)) except: quit "wrong port format"
        stime    = epochTime()
    var
        wordlist = try: paramStr(3).lines.toSeq() except: quit "couldnt open the file"
        server   = newSocket()
    
    addHandler(newColoredLogger())
    try: connect(server, ip, Port(port)) except: quit "couldnt connect to the server"
    info(&"Connected to {getPeerAddr server}")

    handle(server, wordlist)
    info(&"Took {epochTime() - stime:.3f}s")

main()
