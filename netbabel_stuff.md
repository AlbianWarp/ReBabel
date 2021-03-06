# Assumptions made from looking at `don.dump`


- The Netbable **package Type** is determined by the first 4 Bytes of the TCP Payload, unless it is a multiframe package (i.E. a sent/recieved Creature), in this case subsequental frames, dont start with a specific Byte but rather continue the preceding Messages
- All Netbable Packages asside from `PRAY` packages have an a ever increasing `package counter` positioned at an offset of `20`
- Said Package counter is used in server responses
- Netbable packages always have a Header that is 32 Byte in size
- The smalest posible Package contains just of a Header.
- Numbers have a Byte order (endianness) of "little". i.E. the Number `1337` results in the Bytes `3905`(hex) instead of `0539`(hex)

## Header:

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 |PackageType|       ECHO LOAD       |  User ID  |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 | ????????? | Pkg.Count |         Zeros         |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
## "Known" **package Types**:

Assuming that the first 4 Bytes are determining the Package Type, these Package Types can be deduced from the Dump:

|Bytes| CAOS Comand|Sender |Type |
|-|-|-|-|
|09  | - |CS|`PRAYMESG`,`PRAYREQU`,`PRAYCHAT`, `PRAYGLST`, |
|0A  | `NET: LINE` |S| - Login Reply (see 25)|
|0D  | - |CS|User Online Status maybe ?|
|0E  | - |CS|User Online Status maybe ?|
|0F  | - |CS|--|
|_0F_| `NET: UNIK` |C| Request: Get me the User Info for the ID <X> (maybe `NET: UNIK`) ?|
|_0F_| `NET: UNIK` |S| Response: Here are the User Info for the User <X> (response to **0F** request)|
|10| - |C|Control|
|13| - |CS|`NET: ULIN`|
|18  | - |CS|`NET: STAT`|
|_18_| `NET: STAT` |C| Length is always 32 Appart from the `ECHO Load` and the `package counter` the Request seems to be Empty.|
|_18_| `NET: STAT` |S| The Server response does not contain the ECHO Load, but has the `package counter`. |
|1F  | - |S|Package No. 450|
|2102| `NET: RUSO` |CS|Get a Random User ID|
|25  | `NET: LINE` |C|Login Request|
|2D| - |S|Packet No. 721|
|30| - |S|Packet No. 1441|
|35| - |C|Packet No. 1285, Posibly a Live Event?|
|70| - |C|Packet No. 273 Maybe Live Event?|


## Login request Package

A Login Package is gnerated by the Client via net `NET: LINE` Command, it Contains the `UserID` and `Echo Load` (if the Player previously was logged in), the `Package Count`, as well as the `Username` and `Password` and Information on Username and Password Lenght as well as Padding.


In this Package the Player `WizardNorn` tried to authenticate with the Password `12345678`.

### Data

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 |25 00 00 00|00 00 00 00 00 00 00 00|1b 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 |01 00 0a 00|05 00 00 00|00 00 00 00 00 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0030 |01 00 00 00|02 00 00 00|00 00 00 00|0b 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0040 |09 00 00 00|57 69 7a 61 72 64 4e 6f 72 6e|00|31»
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0050  32 33 34 35 36 37 38|00|
     +--+--+--+--+--+--+--+--+
```

`2500000000000000000000001b00000001000a000500000000000000000000000100000002000000000000000b0000000900000057697a6172644e6f726e007300313233343536373800`

### Frame

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 | Msg. Type |   Echo Load (empty)   |  User ID  |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 |   ?????   | Msg.Count |      Zero Padding     |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0030 |   ?????   |   ?????   |   ?????   |len(user)+1|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0040 |len(pass)+1|           Username          |00|⏎
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0050       Password       |00|
     +--+--+--+--+--+--+--+--+
```

## Login Response (Success)

This is a succesfull response to the Login Message sent previously, it Contains Information on the `Hostname or IP Address`, a `Friendly Name` as well as the `Port` of the Game servers (multiple Server can be returned).
These Information are then Stored in the `server.cfg` in the Game/Engine directory.
This mechanism can be used to i.E. aid the Migration to a new server and/or update the Port, or add another Server to the Configuration.

The Server Adress returned in this Example is `localhost` the Port is `1337` and the Friendly Name is `mjolnir`.

### Data

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 |0a 00 00 00|40 52 4b 28 eb 00 00 00|26 09 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 |01 00 0a 00|25 00 00 00|00 00 00 00|00 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0030 |00 00 00 00|01 00 00 00|00 00 00 00|28 00 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0040 |01 00 00 00|01 00 00 00|01 00 00 00|39 05 00 00|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0050 |01 00 00 00|6c 6f 63 61 6c 68 6f 73 74|00|6d 6a»
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0060 »6f 6c 6e 69 72|00|
     +--+--+--+--+--+--+
```
`0a00000040524b28eb0000002609000001000a002500000000000000000000000000000001000000000000002800000001000000010000000100000039050000010000006c6f63616c686f7374006d6a6f6c6e697200`

### Frame

```
      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0000 | Pkg. Type |       Echo Load       |  User ID  |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0020 |   ?????   | Pkg.Count |      Zero Padding     |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0030 |   ?????   |   ?????   |   ?????   |len(payld.)|
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0040 |   ?????   |   ?????   |   ?????   |   Port    |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0050 | Server ID |  Hostname or IP Address  |00|   ⏎
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
0060  Friendly Name |00|
     +--+--+--+--+--+--+
```


## Localhost Server Config `server.cfg`

```
"Server 0 FriendlyName" mjolnir
"Server 0 Host" localhost
"Server 0 ID" 1
"Server 0 Port" 1337
"Server Count" 1
```

## Login Response (Failed)

A "failed" Login Response was not recorded, but via Trial and Error we found out that when, answering a Login Request with an "empty" 28 Byte Payload, the Client handles it like a failed Login, and does not crash.

> We should test if we can add Server Configuration to a failed login response as well.
>

### Data

```
     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 00 |0a 00 00 00|00 00 00 00 00 00 00 00|00 00 00 00|
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 01 |00 00 00 00|05 00 00 00|00 00 00 00 00 00 00 00|
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 02  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00»
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 03  00 00 00 00 00 00 00 00 00 00 00 00|
    +--+--+--+--+--+--+--+--+--+--+--+--+

```

`0a0000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000000000000000000`

### Frame

```
     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 00 | Pkg. Type |       Echo Load       |  User ID  |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 01 |   ?????   | Pkg.Count |      Zero Padding     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 02 |00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00»
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 03  00 00 00 00 00 00 00 00 00 00 00 00|
    +--+--+--+--+--+--+--+--+--+--+--+--+

```
