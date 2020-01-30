# !/usr/bin/python
# -*- coding:utf-8 -*-
# ###########################
# File Name: controller.py
# Author: dingdamu
# Mail: dingdamu@gmail.com
# Created Time: 2019-02-07 16:43:08
# ###########################

import subprocess
from datasketch import HyperLogLog
import numpy as np
import loglog


def readRegister(register, thrift_port):
    p = subprocess.Popen(['docker', 'exec', '-i', 'hh', 'simple_switch_CLI',
                          '--thrift-port', str(thrift_port)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input="register_read %s" % (register))
    reg = list(stdout.strip().split("= ")[1].split("\n")[0].split(", "))
    reg = map(int, reg)
    return reg


hll_reg1 = readRegister("hll_register", 22222)
ll1 = loglog.estimate_cardinality(hll_reg1, 4)
print "Cardinality estimation in S1(LL):"
print ll1
hll1 = HyperLogLog(p=4, reg=np.array(hll_reg1))
print "Cardinality estimation in S1(HLL):"
print hll1.count()

hll_reg2 = readRegister("hll_register", 22223)
ll2 = loglog.estimate_cardinality(hll_reg2, 4)
print "Cardinality estimation in S2(LL):"
print ll2
hll2 = HyperLogLog(p=4, reg=np.array(hll_reg2))
print "Cardinality estimation in S2(HLL):"
print hll2.count()

hll_reg3 = readRegister("hll_register", 22224)
ll3 = loglog.estimate_cardinality(hll_reg3, 4)
print "Cardinality estimation in S3(LL):"
print ll3
hll3 = HyperLogLog(p=4, reg=np.array(hll_reg3))
print "Cardinality estimation in S3(HLL):"
print hll3.count()

hll_tot = HyperLogLog(p=4)
hll_tot.merge(hll1)
hll_tot.merge(hll2)
hll_tot.merge(hll3)
print "Network-wide Cardinality number:"
print hll_tot.count()
