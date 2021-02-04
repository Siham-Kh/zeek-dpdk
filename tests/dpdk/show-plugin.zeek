# @TEST-EXEC: zeek -NN Zeek::Dpdk |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
