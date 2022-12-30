# p4runtime-go-client - WIP CNN interaction
Go client for P4Runtime

**This project is still a work in progress. We make no guarantee for the
  stability of the API and may modify existing functions in the client API. We
  welcome feedback and contributions!.**

For a good place to start, check out the [l2_switch
example](cmd/l2_switch/README.md).


![Alt text](arch.jpg?raw=true "Architecture")

## p4 controller

To make the controller work you have to follow the next steps.
First of all you need to start the mininet

```bash
# from the root of the directory
$ cd ./cmd/controller/mininet
$ make
```

Then you need to open another terminal window, and then start the controller

```bash
# from the root of the directory
$ cd ./cmd/controller/
$ make
```

At this point everything should work, you can test it by going into the mininet terminal and run **pingall** command. No packet should be dropped

```bash
mininet> pingall
```

Then you need to open another terminal window, and then start the cnn

```bash
# from the root of the directory
$ cd ./cmd/controller/cnn
$ conda activate python38
(python48)$ ./lucid.sh
```

Then you need to go back on the Mininet window, and then start an attack

```bash
mininet> h1 hping3 -a 11.0.0.1 --faster 10.42.0.2
```

Then you can connect to localhost:3333 via http to interact with the server via the UI
