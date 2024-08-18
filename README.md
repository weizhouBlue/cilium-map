# cilium-map

A small tool to generically introspect BPF maps without requiring to be aware
of the specific data structures stored inside. Can print the metadata of the
map or its contents in hexadecimal form.

## release note

update to cilium v1.16

## Install

Install from source via `go get`:

```
git clone https://github.com/weizhouBlue/cilium-map.git
cd cilium-map
go build cilium-map.go
```

## Usage

```
cd /sys/fs/bpf/tc/globals/
cilium-map dump ./FILE_NAME
```
