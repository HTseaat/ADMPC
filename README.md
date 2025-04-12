# AD-MPC: Asynchronous Dynamic MPC with Guaranteed Output Delivery

## Setup

1. Install `Docker`_. (For Linux, see `Manage Docker as a non-root user`_ to run ``docker`` without ``sudo``).

2. Install `docker-compose`. 

3. The image will need to be built  (this will likely take a while). 
```
$ docker-compose build admpc
```

## Running tests on local machine

1. You need to start a shell session in a container. 
```
$ docker-compose run --rm admpc bash
```

2. Then, to test the `admpc` code locally, i.e., multiple thread in a single docker container, you need to run the following command with parameters:
      - `num`: Number of nodes, 
      - `ths`: fault-tolerance threshold. 
```
$ pytest tests/test_admpc.py -o log_cli=true --num 4 --ths 1 --curve ed25519
```

## Runing on cloud servers
Please refer to `scripts/control-node.sh` and `scripts/admpc_dynamic_run.py` for detailed instructions on how to run the protocol among cloud servers. 
