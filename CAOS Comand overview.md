# CAOS Comand overview

This Document documents the CAOS Comands and the NetBabel Messages corosponding to it.


# NET: commands that do not generate NetBabel Messages

## NET: ERRA

### Comand Documentation
`NET: ERRA (integer)`
> Returns an error code from the last command. Currently NET: LINE is the only command to set it.
>
> Error codes are:
> 0 - Unknown
> 1 - Connection OK
> 2 - Connection failed, you or the server are offline
> 3 - Connection failed, invalid user name/password
> 4 - Connection failed, you are already logged in elsewhere
> 5 - Connection failed, too many users for server
> 6 - Connection failed, internal error
> 7 - Connection failed, new client version required.
>
> Try NET: RAWE for more detailed diagnostic codes.

## NET: FROM

### Comand Documentation
`NET: FROM (string) resource_name (string)`
> The user who sent the PRAY file which contains the specified resource. If the resource did not arrive as a message over the network via NET: MAKE or NET: EXPO, then this returns an empty string. The user returned by this command is guaranteed in a way that looking at the content of the PRAY file would not be. For example, the "Last Network User" attribute in an exported Creature made with NET: EXPO could be faked.

## NET: HEAD

### Comand Documentation
`NET: HEAD (command)`
> Dump debugging informatino about who is NET: HEARing on what channels.

## NET: HEAR

### Comand Documentation
`NET: HEAR (command) channel (string)`
> The target agent will now accept CAOS messages over the network on the specified channel, and execute their script as appropriate. Use NET: WRIT to send the message.

## NET: HOST

### Comand Documentation
`NET: HOST (string)`
> Returns the hostname, port, id and friendly name on that host that we are currently connected to, or empty string if offline. The fields are space separated, although the last field (friendly name) may contain spaces.


## NET: PASS

### Comand Documentation
`NET: PASS (string)`
> Returns the currently set username, as selected with PASS.

## NET: PASS

### Comand Documentation
`NET: PASS (command) nick_name (string) password (string)`
> Set nickname and password - do this before connecting with NET: LINE. If you set GAME "engine_netbabel_save_passwords" to 1 then the password for each nickname is saved in user.cfg, so you can specify an empty string for the password after the first time. The nickname is saved with the serialised world, so is cleared when you start a new world. You can use NET: PASS to retrieve the user later.

## NET: RAWE

### Comand Documentation
`NET: RAWE (integer)`
> Returns an internal error code from Babel. Only use this for display and diagnostic purpose, use NET: ERRA for documented error codes which you can rely on.

## NET: USER

### Comand Documentation
`NET: USER (string)`
> Returns the user's numeric Babel id, or an empty string if they have never logged in with this world since they last changed user name.

## NET: WHAT

### Comand Documentation
`NET: WHAT (string)`
> For debugging only. Returns a string describing what the upload/query network thread is currently doing. For example, it may be fetching a random online user, or uploading some creature history. Returns an emptry string if it is doing nothing.

## NET: WHOD

### Comand Documentation
`NET: WHOD (command)`
> Dump debugging information about the whose wanted register.

# NET: Commands that generate NetBabel Messages


## NET: LINE

### Comand Documentation
`NET: LINE (command) state (integer)`
> Goes on or offline, connecting or disconnecting from the Babel server. Set to 1 to connect, 0 to disconnect. A NET: USER must be set first. NET: ERRA is set to any error code. While the connection is being made, this command can block for several ticks. This command never runs in an INST.

### Comand Documentation
`NET: LINE (integer)`
> Returns 1 if you are connected to the Babel server, or 0 if you aren't.


### NetBabel Messages

The NetBabel Login Message Request sent by the Client contains just the Username, and Password, as well as the package_count.

#### Example `NET: PASS "MyUsername" "SecretPassword" NET: LINE 1`

Resulting NetBabel Message/Data:

`2500000000000000000000002609000001000a000a00000000000000000000000100000002000000000000000b0000000f0000004d79557365726e616d650053656372657450617373776f726400`

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 |25 00 00 00|00 00 00 00 00 00 00 00|26 09 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0010 |01 00 0a 00|04 00 00 00|00 00 00 00 00 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 |01 00 00 00|02 00 00 00|00 00 00 00|0b 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0030 |0f 00 00 00|4d 79 55 73 65 72 6e 61 6d 65|00|53»
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0040 »65 63 72 65 74 50 61 73 73 77 6f 72 64|00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

- [0:4] is the Package Type `25 00 00 00`
- [5:12] is the Echo Load `00 00 00 00 00 00 00 00` Upon Login this is "empty"
- [13:16] is the Sender user ID `26 09 00 00` this is `00 00 00 00` if you never logged in before
- [17:20] is unknown but always `01 00 0a 00`
- [21:24] is the message_count `04 00 00 00` in this case _4_
- [25:32] is probably Zero padding, always `00 00 00 00 00 00 00 00`
- [33:36] is unknown, but always `01 00 00 00`
- [37:40] is unknown, but always `02 00 00 00`
- [41:44] is unknown, but always `00 00 00 00`
- [45:48] is the Username Length + 1 `0b 00 00 00`
- [49:52] is the Password Length + 1 `0f 00 00 00`
- [53:62] is the Username encoded in _latin-1_ `4d 79 55 73 65 72 6e 61 6d 65`
- [63:63] is a one Byte Zero delimeter `00`
- [64:77] is the Password encoded in _latin-1_ `53 65 63 72 65 74 50 61 73 73 77 6f 72 64`
- [78:78] is one Byte Zero delimeter/padding `00`



## NET: RUSO

### Comand Documentation
`NET: RUSO (command) store_result (variable)`
> Returns (into store_result) a random user who is currently online. Returns an empty string if you're offline, or if you aren't using the Docking Station Babel server module. Since you're online, it can return yourself (especially if you're the only person online!). The user is also only likely to be online - they could have gone offline since the server replied to you.
>
>This is a command rather than an integer r-value because it is blocking. This means that it might take several ticks before the server returns the result. In this sense it is similar to a command like OVER, so it does not run in an INST. You should use LOCK if you don't want your script interrupting.

## NET: STAT

### Comand Documentation
`NET: STAT (command) time_online (variable) users_online (variable) bytes_received (variable) bytes_sent (variable)`
> Returns statistics for the current Babel connection, or -1 if offline. This command can block (doesn't execute in an INST). The statistics are:
> time_online - Time online in milliseconds
> users_online - Number of users currently connected to the server
> bytes_received - Bytes received by the client
> bytes_sent - Bytes sent from the client

## NET: ULIN

### Comand Documentation
`NET: ULIN (integer) user_id (string)`
> Returns 1 if the specified user is online, or 0 if they are offline. This is slow (i.e. has to call the server) unless the user is in the whose wanted register of any agent. Use NET: WHON to add a user to the register.

## NET: UNIK

### Comand Documentation
`NET: UNIK (command) user_id (string) store_result (variable)`
> Returns the specified user's screen or nick name. Returns empty string if offline, or no such user. This command can take many ticks to execute while the server is quizzed, like NET: RUSO.

## NET: WHOF

### Comand Documentation
`NET: WHOF (command) user (string)`
> Removes a user from the whose wanted list for the target agent. See NET: WHON.

## NET: WHON

### Comand Documentation
`NET: WHON (command) user (string)`
> Add a user to the whose wanted register for the target agent. Scripts User Online and User Offline are now called on this agent when that user goes on or offline, or indeed when the local user goes offline. Use NET: WHOF to remove them from the register. This command is blocking, it can take several ticks to return.

## NET: WHOZ

### Comand Documentation
`NET: WHOZ (command)`
> Zap the target agent's whose wanted register, removing all entries.


## NET: EXPO

### Comand Documentation
`NET: EXPO (integer) chunk_type (string) dest_user_id (string)`
> Transwarp the target creature to the given user. The Creature is exported to the warp out directory; this command is very similar to PRAY EXPO. Return value is one of the following:
> 0 for success
> 1 if the creature, or if pregnant any of its offspring, are already on disk in some form. This case won't happen much, if you use a special chunk name like WARP.
> 2 if the user hasn't been online in this world yet / since the user name changed, so we don't know who they are.

> When receiving a creature, use NET: FROM to find out who sent it.


## NET: WRIT

### Comand Documentation
`NET: WRIT (command) user_id (string) channel (string) message_id (integer) param_1 (anything) param_2 (anything)`
> Send a message to a remote machine, as specified by the user identifier. All agents which are NET: HEARing on the given channel will receive the message, and run the appropriate script. If the specified user is offline, then the message is discarded. The FROM variable of the receiving script contains the user id of the sender, as a string. See also MESG WRIT.

### NetBabel Messages

This command is not understood and does not jet work, sadly we dont have a tcpdump for packages generated by this command, so we will have to reverse engineer this one...

the following was found out by fuzzing a little with it.

#### NET: WRIT Experimentation

When executing the `NET: WRIT` command as follows: `NET: WRIT "1337" "moep" 123 "happy" "meili"` via the ingame CAOS Console two things happen,
first a standard online check for the target User ID is made (think of it as an implicit `NET: ULIN "1337"`) and if said User is Online the following Package is sent after which the Client totaly Locks up:

`1e00000040524b28eb0000002609000001000a00000000000000000001000000390500000000000002000000`

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 |1e 00 00 00|40 52 4b 28 eb 00 00 00|26 09 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0010 |01 00 0a 00|00 00 00 00 00 00 00 00|05 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 |39 05 00 00|00 00 00 00|02 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+
```

While it is not fully understood it consistently appears to contain the following Information

- [0:4] is the Package Type `1e 00 00 00`
- [5:12] is the Echo Load `40 52 4b 28 eb 00 00 00`
- [13:16] is the Sender user ID
- [17:28] is unknown but always: `01 00 0a 00 00 00 00 00 00 00 00 00`
- [29:32] is the Package Number, in this case `05 00 00 00`
- [33:36] is the recipient User ID in this case: `39 05 00 00` which translates to `1337`
- [37:44] is unknown as well but always: 00 00 00 00 02 00 00 00


If you echo this Package right back at the Client it answers with:

`1400000040524b28eb0000002609000001000a000000000000000000020001000e000000`

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 |14 00 00 00|40 52 4b 28 eb 00 00 00|26 09 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0010 |01 00 0a 00|00 00 00 00 00 00 00 00|02 00 01 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 |0e 00 00 00|
     +--+--+--+--+
```

- [0:4] is the Package Type `1e 00 00 00`
- [5:12] is the Echo Load `40 52 4b 28 eb 00 00 00`
- [13:16] is the Sender user ID `26 09 00 00`
- [17:36] is not Understood and NOT always the same. `01 00 0a 00 00 00 00 00 00 00 00 00 02 00 01 00 0e 00 00 00`

If you then ECHO That package right back at the client it answers with the following Package and the Client is unlocked again:

`1f00000040524b28eb0000002609000001000a00000000000c00000001000200390500000000000002000000010000002609000001000a00`

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 |1f 00 00 00|40 52 4b 28 eb 00 00 00|26 09 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0010 |01 00 0a 00 00 00 00 00 0c 00 00 00 01 00 02 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 |39 05 00 00 00 00 00 00 02 00 00 00 01 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0030 |26 09 00 00 01 00 0a 00|
     +--+--+--+--+--+--+--+--+
```

- [0:4] is the Package Type `1e 00 00 00`
- [5:12] is the Echo Load `40 52 4b 28 eb 00 00 00`
- [13:16] is the Sender user ID `26 09 00 00`
- [The Rest] is not understood
