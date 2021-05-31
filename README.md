# bpf-map

A small tool to generically introspect BPF maps without requiring to be aware
of the specific data structures stored inside. Can print the metadata of the
map or its contents in hexadecimal form.

## Install

Install from source via `go get`:

```
go get github.com/cilium/bpf-map

git clone https://github.com/weizhouBlue/cilium-map.git
cd cilium-map
go build cilium-map

```


## Usage

```
cd /sys/fs/bpf/tc/globals/
cilium-map dump ./FILE_NAME
```


