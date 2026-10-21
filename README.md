# WLANProject
# WLANProject

This project currently runs using a C program. Please clone the github repository

```
git clone https://github.com/competingthesquares-lol/WLANProject.git
cd WLANProject
./fullnet
```

Then go to http://localhost:8088.

# Explanation

This project was coded in C. All the network protocols and the GET and POST requests were coded manually. 
There are many protocols coded into the short around 700 lines of code this project currently contains. 

# Networking Primer

We begin with explanation of the network protocol itself. Here, there are two main ones we use, which are TCP and UDP. 
TCP (Transmission Control Protocol) is used to reliably send messages, and is the method we adopt to do communication. The TCP has been very optimized already for computers. 
The TCP uses a three-way handshake to truly confirm a successful connection.

On ther other hand, UDP (User Datagram Protocol) is faster, but is also unreliable, as it just sends one datagram continuously with no way to know how to send it over.
We'll see how these work in a second, but first a tangent about file descriptors.

File descriptors (fd) are integers and represent a socket. When we create a socket, we use the socket() function and it returns an integer descriptor.
There are three arguments of socket(). The first two arguments specifies the kind of socket. We usually always set the first argument to AF_INET which represents the Internet protocol.
The second argument is where things get interesting. We usually either choose SOCK_STREAM or SOCK_DGRAM. Specifying SOCK_STREAM means our file descriptor represents a TCP socket, 
while the latter SOCK_DGRAM represents a UDP socket by default. Thus, we always usually choose 0 for the third argument to specify the default protocol.

Thus, whenever you see something along the lines of `fd = socket(AF_INET, SOCK_STREAM, 0)`, we know it is a TCP file descriptor, and `fd = socket(AF_INET, SOCK_DGRAM, 0)` is a UDP file descriptor.

After this first step, we do either one of two things, representing the two things a server can do. It can either wait for a connection from some other client to this server, or it can 
connect to another server. To wait, we do a bind() and then listen(). For the latter, we do a connect().

For both the bind() and connect() function, we require the file descriptor, which is simple enough, but we also require a pointer to the struct sockaddr, and the length of sockaddr.

Here is where things get a little weird. In addition to (struct sockaddr), we also have another struct called (struct sockaddr_in). The idea is that both are technically specifying the same 
block of information, but interpreting it differently. (struct sockaddr) basically treats it as a block of bytes, and that block of bytes is supposed to directly communicate information 
about our network. On the other hand, (struct sockaddr_in) treats our information as a bunch of separate parts, with each part representing its own piece of information. 
To give another analogy, (struct sockaddr) represents a form pdf as a whole, while (struct sockaddr_in) represents the individual fields to fill out.

The point of separating those two structs is that the next step of the network protocol is to fill the necessary information into each field of sockaddr_in, then we have to convert to sockaddr 
so that the computer sees this information now instead as a stream of bytes given to the network protocol to interpret. For sockaddr_in, there are three fields that are important, which are

*.sin_family (we literally just set this to AF_INET)
*.sin_addr.s_addr (a 32-bit unsigned long representing our IPv4 address)
*.sin_port (a 16-bit field representing our port)


