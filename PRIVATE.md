## validation

sudo bpftool net list dev lo

## test

../testenv/testenv.sh
../testenv/testenv.sh  --help

sudo testenv/testenv.sh setup --name=test
eval $(testenv/testenv.sh alias)
t enter
t exec -- ip a
t teardown
t ping

t setup --name=test --vlan --legacy-ip
```
+-----------------------------+                          +-----------------------------+
| Root namespace              |                          | Testenv namespace 'test01'  |
|                             |      From 'test01'       |                             |
|                    +--------+ TX->                RX-> +--------+                    |
|                    | test01 +--------------------------+  veth0 |                    |
|                    +--------+ <-RX                <-TX +--------+                    |
|                             |       From 'veth0'       |                             |
+-----------------------------+                          +-----------------------------+
```


t exec -- socat - 'udp6:[fc00:dead:cafe:1::1]:2000'

## run direct

attached to the interface within the program

cd xdp
sudo go run *.go eth0

## attach to link via ip link and object file

sudo ip link set dev lo xdpgeneric obj bpf_bpfel.o  sec xdp
sudo ip link set dev lo xdpgeneric off

sudo bpftool net list dev lo

llvm-objdump -S bpf_bpfel.o
readelf -a bpf_bpfel.o



