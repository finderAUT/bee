# bee-node

# Installing from source

## Dependencies

### Debian

```sh
apt-get update
apt-get upgrade
apt-get install git build-essential cmake pkg-config librocksdb-dev llvm clang libclang-dev libssl-dev
```

### MacOS

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install cmake
```

### Windows

Open Powershell and execute the following commands:
```sh
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install git --params '/NoAutoCrlf' cmake --installargs 'ADD_CMAKE_TO_PATH=System' llvm
```
Restart Powershell

### Rust

Minimum required version 1.48.

#### Installation (Debian, MacOS)

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### Installation (Windows)

Install Rust from [here](https://www.rust-lang.org/learn/get-started).

#### Update

```sh
rustup update
```

## Compilation

```sh
git clone https://github.com/iotaledger/bee.git --branch mainnet-develop
cd bee/bee-node
```

With dashboard

```sh
cargo build --release --features dashboard
```

Without dashboard
```sh
cargo build --release
```

## Running

```sh
cp config.template.json config.json
../target/release/bee
```

# Using Docker

We also provide a `Dockerfile` that allows you to quickly deploy a Bee node. Please refer to the [Docker](../documentation/docs/getting_started/docker.md) section of the Bee documentation for more information.


###ATTENTION
per default the config `bee/bee-node/config.chrysalis-mainnet.json` is used for the docker image
and not config.json mounted into the container.
Can be changed by adding `--config config.json` at end of command.

```
podman run \
  -v $(pwd)/config.json:/app/config.json:Z \
  -v $(pwd)/storage:/app/storage:Z \
  -v $(pwd)/snapshots:/app/snapshots:Z \
  --name bee2\
  --net=host \
  --ulimit nofile=8192:8192 \
  -d \
 bee:milestone-msg-proof-prod2 \
 --config config.json
```

UIDs of the base image `gcr.io/distroless/cc-debian11:nonroot`:
```
# cat /etc/passwd
root:x:0:0:root:/root:/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin
nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin
```
As can be seen in the bee-node Dockerfile the user `nonroot` is used.
Therefore, for it to have access to the mounts (storage, snapshots) 
we have to make sure the respective user id owns them from the podman user space point of view:
Per default everything will be owned by root.
```
$ podman unshare ls -la

drwxrwxr-x. 1 root root    836  3. Okt 20:02 .
drwx------. 1 root root   1168  3. Okt 19:45 ..
-rw-r--r--. 1 root root   3454  5. Sep 17:11 config-devnet.json
-rw-r--r--. 1 root root   5099  3. Okt 20:02 config.json
drwxr-xr-x. 1 root root     26  5. Sep 17:11 snapshots
drwxr-xr-x. 1 root root      0 25. Sep 17:43 storage
```

To change that execute 
```
$ podman unshare chown 65532:65532 -R storage
$ podman unshare chown 65532:65532 -R snapshots
```

https://www.tutorialworks.com/podman-rootless-volumes/