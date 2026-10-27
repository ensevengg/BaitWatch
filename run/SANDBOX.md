# Sandbox boundary

The runner talks to a local Linux Docker daemon. It creates resources through the Docker API, then starts the container with a Docker attach client on the host and streams the output. The repository's command arguments go only into the container definition. The runner never executes a repository script on the host.

Each scan follows these steps.

1. **Stage a copy.** The runner copies the repository into a disposable directory. It walks the tree with file-descriptor-relative opens that never follow a symlink, even when a file turns into a symlink during the copy. It copies symlinks as symlinks. The copy fails on regular files with more than one hard link, on devices, sockets and FIFOs, and when it passes the limit on entries, bytes, depth or time. It leaves out Git metadata, dependency and cache environments, credential-store directories and real `.env` files, and lists each one in `staging_exclusions`. It keeps `.env.example` and agent hook or settings directories. An excluded path was not scanned. The copy is not an atomic Git snapshot, so a repository that changes during the copy can make staging fail.
2. **Create the network.** The runner creates a uniquely named internal bridge on `10.13.37.0/24` and labels it with the scan. The cage is `.20`. Sinks get fixed addresses, `.53` for DNS and `.9` for HTTP and TLS. The network uses Docker's isolated gateway mode, so the host gets no address on it and the cage cannot reach the host. If the engine still assigns a host gateway, for example because it is older than Docker 28, the scan fails with a setup error. The runner never joins a default or public network, never publishes ports, and never reuses a network that already exists.
3. **Restrict the cage.** The container runs as uid and gid `65532:65532` with a read-only root filesystem and a read-only repository mount. It gets a small writable `/tmp`, drops all capabilities, sets no-new-privileges, and has memory, CPU and PID limits. The runner never mounts the original repository, home directories, credentials, host devices or the Docker socket. It sets the container environment explicitly and copies no host secrets into it.
4. **Bound execution.** By default, stdout and stderr share a 64 KiB budget and the command has 20 seconds. Going over either limit stops the container. The attach client has its own limits and the runner always reaps it. A missing local image is an error. Pull images during trusted setup, before any scan.
5. **Clean up.** The runner removes only the resources this scan created, including when an exception interrupts it. It records cleanup failures. If the runner cannot remove a container, it keeps the staging directory so an operator can recover it. A crash of the process or host can still leave labelled resources behind. Recover them by filtering on the scan label. Never run a global Docker prune.

## Known limits

- The cage cannot reach public addresses or the host over the network. It can still reach the other containers on its own bridge, which are the sinks. This milestone makes no claim of resistance to kernel or container escapes.
- The DNS address has no resolver until the next milestone. The integration test uses a plain HTTP server to check connectivity. That server is not the production sink.
- Later milestones add TLS SNI and body capture, parsing of data hidden in DNS labels, honeytoken attribution, file diffs, model transcript scanning, the decoy's tool loop and the verdict engine.
- The fixed subnet means one scan at a time. A second scan that collides fails closed.
- All mounts inside the container are read-only for now. A later writable trace layer must still use a disposable copy and never expose the original repository.

Docker references: [bridge networks](https://docs.docker.com/engine/network/drivers/bridge/), [SDK containers](https://docker-py.readthedocs.io/en/stable/containers.html) and [SDK networks](https://docker-py.readthedocs.io/en/stable/networks.html).
