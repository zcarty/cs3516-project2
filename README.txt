Zeb Carty and Michael McInerney

Multi-threaded server with the ability to decode QR Codes.

To use:
run 'make server' on CS3516_team4_host1 (port 8010)
run './QRServer <args>'

Anywhere else run 'make client'
run './QRClient <args>'

QRClient will prompt the user for a filepath (user must submit a image file of a QR Code)
If decoded without failure, the server will produce a return code, including the url represented by that QR Code


Notes:
Files required on CS3516_team4_host1:
    server.cpp
    core.jar
    javase.jar
    log.cpp
    decode.cpp
    include.h
    makefile
Files on another vm:
    client.cpp
    include.h
    makefile
    <image of qr code>


Command Line Arguments:
(server/client) • PORT [port number]
(server only)   • RATE [number requests] [number seconds]
(server only)   • MAX USERS [number of users]
(server only)   • TIME OUT [number of seconds]


Return Code Key:
0 - Success. The URL is being returned as specified below.
1 - Failure. Something went wrong and no URL is being returned. The character array length is set
to 0 and no character array is transmitted. This condition can be valid if the image uploaded does not
represent a valid QR code or the client violates our network security requirements.
2 - Timeout. The connection is being closed. A human-readable text message is created and supplied
as the character array. The character array length is set to the length of this human readable message.
3 - Rate Limit Exceeded. An error message about the rate limit being exceed is set in the character
array with the size set to the character array.