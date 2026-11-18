-- displus.lua — displus(DIS 全解)唯一入口
-- Copyright (C) 2026 zhenming(振茗)
-- SPDX-License-Identifier: GPL-2.0-or-later

---------------------------------------------------------------- 模块目录发现
-- 开发模式下读取与displus.lua同级的 modules
local self_src = debug.getinfo(1, "S").source or ""
if self_src:sub(1, 1) == "@" then self_src = self_src:sub(2) end
local self_dir = self_src:match("^(.*[/\\])")

local MODULE_CANDIDATES = {}
if self_dir then
    MODULE_CANDIDATES[#MODULE_CANDIDATES + 1] = self_dir .. "modules\\"
end
MODULE_CANDIDATES[#MODULE_CANDIDATES + 1] =
    (os.getenv("APPDATA") or "") .. [[\Wireshark\plugins\displus_mod\]]

-- 检查 common.luamod 是否存在
local MODDIR = nil
for _, dir in ipairs(MODULE_CANDIDATES) do
    local fh = io.open(dir .. "common.luamod", "r")
    if fh then
        fh:close()
        MODDIR = dir
        break
    end
end

local C = nil
if MODDIR then
    local ok, result = pcall(dofile, MODDIR .. "common.luamod")
    if ok then C = result end
end

if C then
    -- 加载次序:跨族公共记录(records)先于一切 PDU 模块;每族先加载族内
    -- 共享(shared)再加载各 PDU 文件;siman/reliable 依赖 siman/base
    C.load(MODDIR, {
        "enums_core", "enums_data", "country", "records",
        -- 实体信息族(1/4/66/67/72)
        "entity/shared", "entity/state", "entity/collision", "entity/collision_elastic",
        "entity/state_update", "entity/attribute",
        -- 作战族(2/3)
        "warfare/shared", "warfare/fire", "warfare/detonation",
        -- 后勤族(5-10)
        "logistics/shared", "logistics/service", "logistics/resupply", "logistics/repair",
        -- 仿真管理族(11-22,73 / R 系列 51-62)
        "siman/shared", "siman/base", "siman/reliable",
        -- 无线电通信族(25-27,31,32)
        "radio/shared", "radio/transmitter", "radio/signal", "radio/receiver", "radio/intercom",
        -- 分布发射再生族(23/24/28/29)
        "emission/shared", "emission/emission", "emission/designator",
        "emission/iff", "emission/underwater",
        -- 实体管理族(33-36)
        "mgmt/aggregate", "mgmt/isgroupof", "mgmt/transfer", "mgmt/ispartof",
        -- 雷场族(37)
        "minefield/state",
        -- 合成环境族(41)
        "synthenv/process",
    })
end

local displus
if C then
    displus                    = C.proto
    displus.prefs.port         = Pref.uint("监听端口 (DIS UDP port)", 3000, "DIS 使用的 UDP 端口,须与内置 dis 一致")
    displus.prefs.show_builtin = Pref.bool("显示内置英文树 (Show built-in English tree)", true,
        "每包先调用内置 dis 解析器生成英文树(dis.* 过滤器可用)")
    displus.prefs.show_cn      = Pref.bool("生成中文树 (Show Chinese tree)", true,
        "在英文树之后追加中文字段树")
end

local cur_port = 3000

---------------------------------------------------------------- 路由器
local function dissector(tvb, pinfo, tree)
    -- 与内置一致:短于 12 字节不判为 DIS
    if tvb:len() < 12 then return 0 end

    if C and displus.prefs.show_builtin then
        -- 先出内置dis解析;单独 pcall 防止内置异常中断中文树
        pcall(function() C.builtin:call(tvb, pinfo, tree) end)
    else
        -- 只中文模式:协议列仍标 DIS(Info 列不动)
        pinfo.cols.protocol = "DIS"
    end

    if not (C and displus.prefs.show_cn) then
        return tvb:len()
    end

    local pdu_type = tvb(2, 1):uint()
    local name     = C.PDU_NAME[pdu_type]
        or (C.PDU_TYPE_TBL[pdu_type])
        or string.format("未知类型 %d", pdu_type)

    local root     = tree:add(displus, tvb())
    root:append_text(" — " .. name)

    local ok, err = pcall(function()
        C.dissect_header(tvb, root)

        local body = root:add(tvb(12), name .. " PDU")
        local fn = C.BODY[pdu_type]
        local consumed
        if fn then
            consumed = fn(tvb, body, 12, pinfo)
        else
            if tvb:len() > 12 then
                body:add(C.proto.fields.raw, tvb(12))
            end
            consumed = 12
        end
        if consumed and consumed < tvb:len() then
            body:add(tvb(consumed),
                string.format("[提示] 尾部 %d 字节未解析(同一数据报多 PDU?)", tvb:len() - consumed))
        end
    end)

    if not ok then
        root:add(tvb(), "[DIS中文] 解析中断: " .. tostring(err))
    end
    return tvb:len()
end

---------------------------------------------------------------- 注册与偏好变更
if C then
    function displus.dissector(tvb, pinfo, tree)
        return dissector(tvb, pinfo, tree)
    end

    DissectorTable.get("udp.port"):add(cur_port, displus)

    function displus.prefs_changed()
        local new_port = displus.prefs.port
        if new_port ~= cur_port then
            pcall(function()
                DissectorTable.get("udp.port"):remove(cur_port, displus)
            end)
            DissectorTable.get("udp.port"):add(new_port, displus)
            cur_port = new_port
        end
    end

    -- 每次打开/重载抓包文件前由 Wireshark 调用:清空跨包上下文。
    function displus.init()
        C.clear_ctx()
    end
else
    -- 模块目录缺失:注册一个仅显示提示,不抛错
    local stub = Proto("displus", "DIS 协议中文字段树(模块缺失)")
    function stub.dissector(tvb, pinfo, tree)
        if tvb:len() < 12 then return 0 end
        tree:add(stub, tvb(),
            "[DIS中文] 模块目录缺失:未找到 common.luamod(候选: "
            .. table.concat(MODULE_CANDIDATES, " ; ") .. ")")
        return tvb:len()
    end

    DissectorTable.get("udp.port"):add(3000, stub)
end
