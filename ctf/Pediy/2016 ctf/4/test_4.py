#!/usr/bin/env python
# -*- coding: utf-8 -*-
import md5
import binascii
import time
#程序参考来自https://bbs.pediy.com/thread-213791.htm   〇〇木一
p1 = "6ED41B695F4EE8AA95F6AFCE321A62D9021874951FC24D333CF03BECE9814B9C"
p1 += "0F475CADD909B087539BF2E30F01928DC2F50CDD42CCAFB4D5E486D39A0B6263"
p1 += "A7D41B695F4EE8AA95F6AFCE321A62D9021874951FC24D3338F03BECED814B9C"
p1 += "0B475CADDD09B087579BF2E30B01928DC2F50CDD42CCAFB4D5E486D39A0B6263"
p1 += "A7D41B695F4EE8AA95F6AFCE321A62D9021874951FC24D3338F03BECE9814B9C"
p1 += "0F475CADD909B087539BF2E30F01928DC2F50CDD42CCAFB4D5E486D39A0B6263"
p1 += "A7D41B695B4EE8AA91F6AFCE361A62D9021874951FC24D3338F03BECE9814B9C"
p1 += "0B475CADDD09B087579BF2E30B01928DC6F50CDD42CCAFB4D5E486D39A0B6263"

p2 = "D805F66AE7A20B9B548CDA82BDB6A846B1362D55F78163FC3F0CFE0B4B50E217"
p2 += "F2E1275B46731CD0E5D78DC9F2709453814C3246A002DB1C450991C496F2A8E8"
p2 += "D905F66BE7A20A9B548CDA82BDB7A946B0362D54F78163FC3E0CFE0B4B50E317"
p2 += "F2E0265A47731CD1E5D68CC8F2709553804C3347A002DB1C440891C496F2A9E8"
p2 += "D904F66AE7A20A9B558CDB83BCB6A946B0372D55F78163FD3E0DFE0B4A50E317"
p2 += "F3E0275B46731DD0E4D78CC8F3709553804C3347A003DB1D450891C496F2A9E8"
p2 += "D904F66AE6A30A9A548CDB82BCB7A946B0372C54F68162FD3E0DFE0A4A50E217"
p2 += "F2E1275B47721CD0E5D78CC9F2709453814D3347A003DB1C440891C5979AA8E8"

#生成迷宫
pp1 = binascii.a2b_hex(p1.encode())
pp2 = binascii.a2b_hex(p2.encode())
pp3 = ""
def ror2(a):
    return ((a&3)<<6)|(a>>2) & 0xFF

for i in range(len(pp1)):
    pp3+=chr(ror2(ord(pp1[i])) ^ ord(pp2[i]))
print(len(pp3))

#16字节一行打印
for i in range(16):
    ps = ""
    for j in range(16):
        ps+=binascii.b2a_hex(pp3[i*16+j]).upper()
    print(ps)

x = 0
y = 0
x0 = 0
y0 = 0
t = [(0,-1),(1,0),(0,1),(-1,0)]
#打印程序指定的道路
path = ""
while(ord(pp3[y*16+x]) != 0x58):
    for i in range(4):
        xx = x + t[i][0]
        yy = y + t[i][1]
        if(xx >= 0 and xx < 16 and yy < 16 and yy >=0 and (xx != x0 or yy != y0)):
            if ord(pp3[yy*16+xx]) != 0x30:
                path += str(i)
                x0 = x
                y0 = y
                x = xx
                y = yy
                break
print(path)

#按照之前的走法，将其合并为每四步为一个字节    one byte for 4 steps,
pn0 = ""
for i in range(23):
    a = 0
    for j in range(4):
        a = (a | int(path[i*4+j])<<((3-j)*2))&0xFF
    pn0 += chr(a)

print(binascii.b2a_hex(pn0).upper())

#处理输入
## 在程序中存在以下操作
## 对前七位进行MD5操作，并循环扩展到0x17位，
## 然后剩余23位与44 AD 5C CC 12 90 73 8D 47 81 E3 89 84 9C DF F9 47 6A B6 9E 11 30 27 sn0进行xor得到sn
## 然后MD5与sn进行xor得到sn_1
## 存在 path = md5[x1] ^ x2 ^ sn0

def getmd5(src):
    m1 = md5.new()
    m1.update(src)
    ret = m1.digest()
    ret = ret + ret[0:7]
    return ret

pn1 = binascii.a2b_hex("44AD5CCC1290738D4781E389849CDFF9476AB69E113027")
pnx=""
#因为是xor操作，有可逆性，所以我们直接得到他之前的值
for i in range(23):
    pnx += chr(ord(pn0[i])^ord(pn1[i]))
print("pnx:", binascii.b2a_hex(pnx).upper())

def xorpm(pm):
    global pnx
    pno=""
    for i in range(23):
        pno += chr(ord(pnx[i])^ord(pm[i]))
    return pno

def isstr(s):
    for a in s:
        aa = ord(a)
        if aa < 32 or aa > 126:
            return False
    return True

# 枚举,
tab='0456123789abcdef'
t0 = time.time();
for a0 in tab:
  for a1 in tab:
    for a2 in tab:
      for a3 in tab:
        for a4 in tab:
          for a5 in tab:
            for a6 in tab:
              aaa=a0+a1+a2+a3+a4+a5+a6
              pppp=xorpm(getmd5(aaa))
              if isstr(pppp):
                print(aaa+pppp)
                break