# -*- coding: utf-8 -*-
"""gen_all_pdus.py — 生成覆盖全部完整字段树 PDU 的 DIS 抓包样本(每类一包)

用法: python -I tools/gen_all_pdus.py
产出: all_pdus.pcap(53 包,每包一个 PDU 类型,body 按 IEEE 1278.1-2012 最小合法构造)
"""
import struct
from pathlib import Path

def f32(x): return struct.pack('!f', x)
def vec3f(x, y, z): return struct.pack('!fff', x, y, z)
def vec3d(x, y, z): return struct.pack('!ddd', x, y, z)

def dis_header(version, ex, pdu_type, family, length):
    if version < 7:
        tail = b'\x00\x00'
    else:
        tail = b'\x0f\x00'  # PDU Status 位组 + 1 字节填充
    return bytes([version, ex, pdu_type, family]) + struct.pack('!IH', 0, length) + tail

def entity_id(site=1001, app=1, e=11): return struct.pack('!HHH', site, app, e)
def event_id(site=1001, app=1, num=1): return struct.pack('!HHH', site, app, num)
def entity_type(k, d, c=0, cat=1, sub=0, sp=0, ex=0): return struct.pack('!BBHBBBB', k, d, c, cat, sub, sp, ex)
def sim_addr(site=1001, app=1): return struct.pack('!HH', site, app)
def clock_time(hour=0, raw=1): return struct.pack('!II', hour, raw)  # raw bit0=绝对

def pdu(pdu_type, family, body, version=7):
    return dis_header(version, 1, pdu_type, family, 12 + len(body)) + body

def packet(payload, idx=0):
    udp = struct.pack('!HHHH', 3001, 3000, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0x1234, 0, 64, 17, 0,
                     bytes([192, 168, 1, 10]), bytes([224, 0, 0, 1]))
    eth = bytes.fromhex('01505044010a0200505e0a0f0800')
    return eth + ip + udp

# ---------------------------------------------------------------- 构造器
def es_body(kind=1, domain=1, caps=0x1C5):
    b = entity_id() + bytes([1, 0])                       # force=友方, 0 变参数
    b += entity_type(kind, domain) + entity_type(0, 0)     # 实体类型 + 备选
    b += vec3f(1, 0, 0) + vec3d(10, 20, 30) + vec3f(0, 0, 0)
    b += struct.pack('!I', 0x1)                            # 外观
    b += bytes([3]) + b'\x00' * 15 + vec3f(0, 0, 0) + vec3f(0, 0, 0)  # DR 40B
    b += bytes([1]) + b'TANK-01'.ljust(11, b' ')           # 标记 12B
    b += struct.pack('!I', caps)
    return b

def collision_body():
    return (entity_id() + entity_id(1001, 1, 99) + event_id()
            + bytes([1, 0]) + vec3f(-5, 0, 0) + f32(1500.0) + vec3f(0, 1, 0))

def collision_elastic_body():
    b = entity_id() + entity_id(1001, 1, 12) + event_id(num=5)
    b += b'\x00\x00' + vec3f(2.5, 0, 0) + f32(1200.0) + vec3f(0.1, 0.2, 0.3)
    b += struct.pack('!6f', 1, 0, 0, 1, 0, 1) + vec3f(0, 0, 1) + f32(0.85)
    return b

def es_update_body():
    return (entity_id() + bytes([0, 0]) + vec3f(2, 0, 0) + vec3d(11, 21, 31)
            + vec3f(0.5, 0, 0) + struct.pack('!I', 0x200))

def attribute_body():
    b = sim_addr() + b'\x00' * 6 + bytes([23, 7]) + struct.pack('!I', 3500) + bytes([0, 0])
    b += struct.pack('!H', 1) + entity_id() + struct.pack('!H', 1)
    b += struct.pack('!IH', 3500, 40) + b'\x00\x00' + bytes([3, 2, 1, 0])
    b += struct.pack('!5f', 4.189, 4.451, 0.0, 1.5708, -60.0) + b'\x00' * 8
    return b

def burst_desc():
    return entity_type(2, 2) + struct.pack('!HHHH', 1000, 2000, 1, 2)

def fire_body():
    return (entity_id() + entity_id(1001, 1, 99) + entity_id(1001, 1, 50) + event_id(num=3)
            + struct.pack('!I', 9) + vec3d(10, 20, 30) + burst_desc() + vec3f(90, 0, 0) + f32(500.0))

def detonation_body():
    b = entity_id() + entity_id(1001, 1, 99) + entity_id(1001, 1, 50) + event_id(num=3)
    b += vec3f(90, 0, 0) + vec3d(10.5, 20.5, 30.5) + burst_desc() + vec3f(0.5, 0, 0)
    b += bytes([2, 0]) + b'\x00\x00'                     # result=近炸, 0 VP, pad16(v7)
    return b

def supply_quantities(n=1):
    b = b''
    for i in range(n):
        b += entity_type(6, 0, cat=1 + i) + bytes([10 + i])
    return b

def logistics_body(pdu_type):
    if pdu_type == 5:
        return entity_id(1001, 1, 7) + entity_id(1001, 1, 8) + bytes([1, 1]) + b'\x00\x00' + supply_quantities()
    if pdu_type in (6, 7):
        return entity_id(1001, 1, 7) + entity_id(1001, 1, 8) + bytes([1]) + b'\x00\x00\x00' + supply_quantities()
    if pdu_type == 8:
        return entity_id(1001, 1, 7) + entity_id(1001, 1, 8)
    if pdu_type == 9:
        return entity_id(1001, 1, 7) + entity_id(1001, 1, 8) + struct.pack('!H', 120) + b'\x00\x00'
    if pdu_type == 10:
        return entity_id(1001, 1, 7) + entity_id(1001, 1, 8) + bytes([1]) + b'\x00\x00\x00'
    return b''

def siman_pair(): return entity_id() + entity_id(1001, 1, 99)

def siman_body(pdu_type):
    b = siman_pair()
    if pdu_type in (11, 12): return b + struct.pack('!I', 9)
    if pdu_type == 13: return b + clock_time() + clock_time() + struct.pack('!I', 9)
    if pdu_type == 14: return b + clock_time() + bytes([1, 0x01]) + b'\x00\x00' + struct.pack('!I', 9)
    if pdu_type == 15: return b + struct.pack('!HH', 1, 2) + struct.pack('!I', 9)
    if pdu_type == 16: return b + struct.pack('!II', 9, 71) + struct.pack('!II', 0, 0)
    if pdu_type == 17: return b + struct.pack('!II', 9, 4) + struct.pack('!II', 0, 0)
    if pdu_type == 18: return b + struct.pack('!II', 9, 3600) + struct.pack('!II', 0, 0)
    if pdu_type in (19, 20): return b + struct.pack('!II', 9, 0) + struct.pack('!II', 0, 0)
    if pdu_type == 21: return b + struct.pack('!II', 73, 0) + struct.pack('!II', 0, 0)
    if pdu_type == 22: return b + struct.pack('!II', 0, 0)
    # R 系列
    if pdu_type in (51, 52): return b + bytes([0]) + b'\x00\x00\x00' + struct.pack('!I', 9)
    if pdu_type == 53: return b + clock_time() + clock_time() + bytes([0]) + b'\x00\x00\x00' + struct.pack('!I', 9)
    if pdu_type == 54: return b + clock_time() + bytes([1, 0x01, 0]) + b'\x00' + struct.pack('!I', 9)
    if pdu_type == 55: return b + struct.pack('!HH', 1, 2) + struct.pack('!I', 9)
    if pdu_type == 56: return b + bytes([0]) + b'\x00\x00\x00' + struct.pack('!II', 9, 71) + struct.pack('!II', 0, 0)
    if pdu_type == 57: return b + struct.pack('!II', 9, 4) + struct.pack('!II', 0, 0)
    if pdu_type == 58: return b + bytes([0]) + b'\x00\x00\x00' + struct.pack('!II', 9, 3600) + struct.pack('!II', 0, 0)
    if pdu_type in (59, 60): return b + bytes([0]) + b'\x00\x00\x00' + struct.pack('!II', 9, 0) + struct.pack('!II', 0, 0)
    if pdu_type == 61: return b + struct.pack('!II', 73, 0) + struct.pack('!II', 0, 0)
    if pdu_type == 62: return b + struct.pack('!II', 0, 0)
    if pdu_type == 73:
        return (b + bytes([0, 0, 1, 0]) + struct.pack('!HH', 6, 6) + struct.pack('!I', 9)
                + bytes([1, 0]) + struct.pack('!H', 0))
    return b''

def radio_entity_type(): return entity_type(7, 0, 0, 1)

def transmitter_body():
    b = entity_id() + struct.pack('!H', 5) + radio_entity_type() + bytes([2, 1]) + b'\x00\x00'
    b += vec3d(10, 20, 30) + vec3f(1, 0, 0) + struct.pack('!HH', 0, 0)
    b += struct.pack('!Q', 240000000) + f32(25000.0) + f32(10.0)
    b += struct.pack('!HHHH', 0, 0, 0, 0) + struct.pack('!HH', 0, 0x8001) + bytes([0]) + b'\x00\x00\x00'
    return b

def signal_body():
    return (entity_id() + struct.pack('!H', 5) + struct.pack('!HH', 0x4000 | 4, 0)
            + struct.pack('!I', 8000) + struct.pack('!HH', 40, 5) + b'\x01\x02\x03\x04\x05')

def receiver_body():
    return (entity_id() + struct.pack('!H', 5) + struct.pack('!H', 2) + b'\x00\x00'
            + f32(-85.5) + entity_id(1001, 1, 12) + struct.pack('!H', 6))

def intercom_control_body():
    return (bytes([1, 1]) + entity_id() + struct.pack('!H', 3) + bytes([0, 5, 1, 1])
            + entity_id(1001, 1, 12) + struct.pack('!HH', 4, 1))

def emission_body():
    b = entity_id() + event_id(num=4) + bytes([0, 1]) + b'\x00\x00'
    b += bytes([0, 1]) + b'\x00\x00' + struct.pack('!HBB', 5, 3, 1) + vec3f(0, 0, 0)  # 系统
    b += bytes([0, 1]) + struct.pack('!H', 3) + struct.pack('!10f', 3e9, 2e6, 55, 350, 1, 0, 0.5, 0, 0.1, 0)
    b += bytes([4]) + bytes([0]) + bytes([0]) + b'\x00' + struct.pack('!I', 0)  # 波束尾
    return b

def designator_body():
    b = entity_id() + struct.pack('!H', 5) + entity_id(1001, 1, 99) + struct.pack('!H', 0x1234)
    b += f32(500.0) + f32(1.06) + vec3f(0, 0, 0) + vec3d(10, 20, 30) + bytes([3]) + b'\x00\x00\x00' + vec3f(0, 0, 0)
    return b

def iff_body(version=7):
    b = entity_id() + event_id(num=5) + vec3f(0, 0, 0)
    b += struct.pack('!HHBB', 4, 0, 0, 0) + bytes([0xA5, 0x3C])
    b += bytes([0x81, 0x00, 0x0F, 0x00]) + struct.pack('!6H', 0x2110, 0x4321, 0x6543, 0x2001, 0x1234, 0x8765)
    return b

def underwater_body():
    b = entity_id() + event_id(num=6) + bytes([0, 0]) + struct.pack('!H', 0) + bytes([0, 1, 0, 1])
    b += struct.pack('!HH', 300, 300) + f32(0.0)                       # 1 轴(当前/指令转速 + 变化率)
    b += bytes([0, 1]) + b'\x00\x00' + struct.pack('!HBB', 5, 3, 1) + vec3f(0, 0, 0)  # 1 系统 1 波束
    b += bytes([0, 1]) + b'\x00\x00' + struct.pack('!HH', 3, 0) + struct.pack('!4f', 0.5, 0.1, 0.3, 0.2)  # 波束
    return b

def aggregate_body():
    b = struct.pack('!HHH', 2001, 1, 1) + bytes([1, 1]) + entity_type(1, 1, 225, 8, 2, 1)
    b += struct.pack('!I', 0) + bytes([1]) + b'1ST ARMOR DIV'.ljust(31, b' ')
    b += vec3f(100, 200, 0) + vec3f(0, 0, 0) + vec3d(10, 20, 30) + vec3f(0, 0, 0)
    b += struct.pack('!HHHH', 0, 0, 0, 0) + struct.pack('!I', 0)
    return b

def isgroupof_body():
    b = struct.pack('!HHH', 2001, 1, 2) + bytes([1, 1]) + struct.pack('!I', 0) + struct.pack('!dd', 39.9, 116.4)
    b += struct.pack('!H', 42) + struct.pack('!hhh', 100, -50, 0) + struct.pack('!I', 1)
    b += struct.pack('!bbb', 10, -5, 0) + struct.pack('!b', 20) + struct.pack('!bbbb', 5, -3, 2, -1)
    return b

def transfer_body():
    return (entity_id() + entity_id(1001, 1, 99) + struct.pack('!IBB', 9, 0, 1)
            + entity_id(1001, 1, 50) + struct.pack('!I', 0))

def ispartof_body():
    b = struct.pack('!HHH', 1001, 1, 7) + entity_id(1001, 1, 99) + struct.pack('!HH', 1, 2)
    b += vec3f(1.5, -2.5, 0) + struct.pack('!HH', 3, 4) + entity_type(1, 1, 225)
    return b

def minefield_body():
    b = struct.pack('!HHH', 3001, 1, 1) + struct.pack('!H', 1) + bytes([1, 1])
    b += entity_type(8, 0) + struct.pack('!H', 1) + vec3d(10, 20, 30) + vec3f(0.5, 0, 0)
    b += struct.pack('!HH', 4, 1) + struct.pack('!ff', -100.5, -200.25) + entity_type(6, 0)
    return b

def env_process_body():
    b = struct.pack('!HHH', 4001, 1, 1) + entity_type(4, 0) + bytes([1, 0x03]) + struct.pack('!HH', 0, 1)
    return b

# ---------------------------------------------------------------- PDU -> (类型, 家族, body)
ALL = []
# 实体信息(1)
ALL += [(1, 1, es_body()), (4, 1, collision_body()), (66, 1, collision_elastic_body()),
        (67, 1, es_update_body()), (72, 1, attribute_body())]
# 作战(2)
ALL += [(2, 2, fire_body()), (3, 2, detonation_body())]
# 后勤(3)
ALL += [(t, 3, logistics_body(t)) for t in (5, 6, 7, 8, 9, 10)]
# 仿真管理(5) + 可靠(10) + 73
ALL += [(t, 5, siman_body(t)) for t in (11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22)]
ALL += [(t, 10, siman_body(t)) for t in (51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62)]
ALL += [(73, 5, siman_body(73))]
# 无线电(4)
ALL += [(25, 4, transmitter_body()), (26, 4, signal_body()), (27, 4, receiver_body()),
        (31, 4, signal_body()), (32, 4, intercom_control_body())]
# 分布发射(6)
ALL += [(23, 6, emission_body()), (24, 6, designator_body()), (28, 6, iff_body()), (29, 6, underwater_body())]
# 实体管理(7)
ALL += [(33, 7, aggregate_body()), (34, 7, isgroupof_body()), (35, 7, transfer_body()), (36, 7, ispartof_body())]
# 雷场(8)
ALL += [(37, 8, minefield_body())]
# 合成环境(9)
ALL += [(41, 9, env_process_body())]

def main():
    out = Path(__file__).resolve().parent.parent / 'samples' / 'all_pdus.pcap'
    out.parent.mkdir(parents=True, exist_ok=True)
    pkts = [packet(pdu(t, fam, body), i) for i, (t, fam, body) in enumerate(ALL)]
    with open(out, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)
    print(f'OK {out} ({len(pkts)} packets)')

if __name__ == '__main__':
    main()
