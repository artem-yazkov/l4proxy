## L4 Proxy test project

#### Description
This is demo project realized simple UDP to TCP proxy

#### Build
```
$ make
gcc -D_GNU_SOURCE -std=c11 -Wall -Wextra l4proxy.c -o l4proxy
```
#### Test
You can use `netcat` tool on both upstream/downstream ends.
Try to do next steps
```
# listen TCP on 8082 port. This is upstream end
nc -l -p 8082 # use it on UPSTREAM. First terminal

# run l4proxy. It should connect to the UPSTREAM immedieately
./l4proxy --down 0.0.0.0:8081 --up 127.0.0.1:8082 --prefix Life --log ./ligfile.txt 

# now push UDP message on 8081
echo  " is far too important a thing ever to talk seriously about (O. Wilde)" | nc -cu 127.0.0.1 8081

# then upstream should receive the message with prefix
$ nc -l -p 8082
Life is far too important a thing ever to talk seriously about (O. Wilde) 
```
