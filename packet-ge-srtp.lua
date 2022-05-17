--[[
	BSD 3-Clause License

	Copyright (c) 2022, Victor Tseng (https://github.com/Palatis/packet-ge-srtp.git) 
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	1. Redistributions of source code must retain the above copyright notice, this
	list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright notice,
	this list of conditions and the following disclaimer in the documentation
	and/or other materials provided with the distribution.

	3. Neither the name of the copyright holder nor the names of its
	contributors may be used to endorse or promote products derived from
	this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
	FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
	CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
	OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]
--[[
	NOTE: this dissector is only tested on FANUC Robot Controller R-j30iB

	TODO: support multi-packet extended response message
]]

do
	assert (set_plugin_info and Pref.range, "This dissector (GE-FANUC - Service Request Transfer Protocol) requires Wireshark 3.x or newer.")

    --
    -- constants
    --
    local DISSECTOR_VERSION         = "0.0.1"

    local DEFAULT_GESRTP_PORT       = 60008

	-- 
	-- misc
	-- 

	-- cache globals to local for speed
	local _F = string.format

    -- wireshark API globals
	local Pref = Pref

	-- register version info with wireshark
	set_plugin_info({version = DISSECTOR_VERSION})


	---
	--- enums
	---
	local PKT_TYPE_INIT 	            = 0x00
	local PKT_TYPE_INIT_ACK             = 0x01
	local PKT_TYPE_REQ		            = 0x02
	local PKT_TYPE_REQ_ACK	            = 0x03
	local PKT_TYPE_UNKNOWN              = 0x08

	local pkt_type_str = {
		[PKT_TYPE_INIT]                 = "INIT",
		[PKT_TYPE_INIT_ACK]             = "INIT_ACK",
		[PKT_TYPE_REQ]                  = "REQ",
		[PKT_TYPE_REQ_ACK]              = "REQ_ACK",
		[PKT_TYPE_UNKNOWN]              = "UNKNOWN",
	}

	local MSG_TYPE_SHORT				= 0xc0
	local MSG_TYPE_SHORT_ACK			= 0xd4
	local MSG_TYPE_EXTENDED				= 0x80
	local MSG_TYPE_EXTENDED_ACK			= 0x94
	local MSG_TYPE_SHORT_ERR			= 0xd1

	local msg_type_str = {
		[MSG_TYPE_SHORT]				= "SHORT",
		[MSG_TYPE_SHORT_ACK]			= "SHORT_ACK",
		[MSG_TYPE_SHORT_ERR]			= "SHORT_ERR",
		[MSG_TYPE_EXTENDED]				= "EXTENDED",
		[MSG_TYPE_EXTENDED_ACK]			= "EXTENDED_ACK",
	}

	local SVC_TYPE_PLC_SHORT_STATUS     = 0x00 -- PLC short status request
	local SVC_TYPE_GET_PROGNAME  	    = 0x03 -- get control program names
	local SVC_TYPE_READ_SYS_MEM         = 0x04 -- read system memory
	local SVC_TYPE_READ_TASK_MEM	    = 0x05 -- read task memroy
	local SVC_TYPE_READ_PROG_MEM	    = 0x06 -- read program memory
	local SVC_TYPE_WRITE_SYS_MEM	    = 0x07 -- write system memory
	local SVC_TYPE_WRITE_TASK_MEM	    = 0x08 -- write task memory
	local SVC_TYPE_WRITE_PROG_MEM	    = 0x09 -- write program block memory
	local SVC_TYPE_PROG_LOGON		    = 0x20 -- programmer logon
	local SVC_TYPE_CHANGE_PRIV		    = 0x21 -- change PLC CPU privilege level
	local SVC_TYPE_SET_CPU_ID		    = 0x22 -- set control ID (CPU ID)
	local SVC_TYPE_SET_PLC_RUN		    = 0x23 -- set PLC (run vs stop)
	local SVC_TYPE_SET_PLC_TIME		    = 0x24 -- set PLC time / date
	local SVC_TYPE_GET_TIME			    = 0x25 -- get PLC time / data
	local SVC_TYPE_GET_FAULT		    = 0x38 -- get fault table
	local SVC_TYPE_CLR_FAULT		    = 0x39 -- clear fault table
	local SVC_TYPE_PROG_STORE		    = 0x3f -- program store (upload from PLC)
	local SVC_TYPE_PROG_LOAD		    = 0x40 -- program load (download to PLC)
	local SVC_TYPE_GET_INFO			    = 0x43 -- get controller type and id information
	local SVC_TYPE_TOGGLE_FORCE_SYS_MEM = 0x44 -- toggle force system memory

	local svc_type_str = {
		[SVC_TYPE_PLC_SHORT_STATUS]	    = "PLC_SHORT_STATUS",
		[SVC_TYPE_GET_PROGNAME]         = "GET_PROGNAME",
		[SVC_TYPE_READ_SYS_MEM]         = "READ_SYS_MEM",
		[SVC_TYPE_READ_TASK_MEM]        = "READ_TASK_MEM",
		[SVC_TYPE_READ_PROG_MEM]        = "READ_PROG_MEM",
		[SVC_TYPE_WRITE_SYS_MEM]        = "WRITE_SYS_MEM",
		[SVC_TYPE_WRITE_TASK_MEM]       = "WRITE_TASK_MEM",
		[SVC_TYPE_WRITE_PROG_MEM]       = "WRITE_PROG_MEM",
		[SVC_TYPE_PROG_LOGON]           = "PROG_LOGON",
		[SVC_TYPE_CHANGE_PRIV]          = "CHANGE_PRIV",
		[SVC_TYPE_SET_CPU_ID]           = "SET_CPU_ID",
		[SVC_TYPE_SET_PLC_RUN]          = "SET_PLC_RUN",
		[SVC_TYPE_SET_PLC_TIME]         = "SET_PLC_TIME",
		[SVC_TYPE_GET_TIME]             = "GET_TIME",
		[SVC_TYPE_GET_FAULT]            = "GET_FAULT",
		[SVC_TYPE_CLR_FAULT]            = "CLR_FAULT",
		[SVC_TYPE_PROG_STORE]           = "PROG_STORE",
		[SVC_TYPE_PROG_LOAD]            = "PROG_LOAD",
		[SVC_TYPE_GET_INFO]             = "GET_INFO",
		[SVC_TYPE_TOGGLE_FORCE_SYS_MEM] = "TOGGLE_FORCE_SYS_MEM",
	}

	local SELECTOR_TYPE_BIT_I           = 0x46
	local SELECTOR_TYPE_BIT_Q           = 0x48
	local SELECTOR_TYPE_BIT_M           = 0x4c
	local SELECTOR_TYPE_BIT_T           = 0x4a
	local SELECTOR_TYPE_BIT_SA          = 0x4e
	local SELECTOR_TYPE_BIT_SB          = 0x50
	local SELECTOR_TYPE_BIT_SC          = 0x52
	local SELECTOR_TYPE_BIT_S           = 0x54
	local SELECTOR_TYPE_BIT_G           = 0x56
	local SELECTOR_TYPE_BYTE_I          = 0x10
	local SELECTOR_TYPE_BYTE_Q          = 0x12
	local SELECTOR_TYPE_BYTE_M          = 0x16
	local SELECTOR_TYPE_BYTE_T          = 0x14
	local SELECTOR_TYPE_BYTE_SA         = 0x18
	local SELECTOR_TYPE_BYTE_SB         = 0x1a
	local SELECTOR_TYPE_BYTE_SC         = 0x1c
	local SELECTOR_TYPE_BYTE_S          = 0x1e
	local SELECTOR_TYPE_BYTE_G          = 0x38
	local SELECTOR_TYPE_WORD_AI         = 0x0a
	local SELECTOR_TYPE_WORD_AQ         = 0x0c
	local SELECTOR_TYPE_WORD_R          = 0x08


	local selector_type_str = {
		[SELECTOR_TYPE_BIT_I]           = "BIT_I",
		[SELECTOR_TYPE_BIT_Q]           = "BIT_Q",
		[SELECTOR_TYPE_BIT_M]           = "BIT_M",
		[SELECTOR_TYPE_BIT_T]           = "BIT_T",
		[SELECTOR_TYPE_BIT_SA]          = "BIT_SA",
		[SELECTOR_TYPE_BIT_SB]          = "BIT_SB",
		[SELECTOR_TYPE_BIT_SC]          = "BIT_SC",
		[SELECTOR_TYPE_BIT_S]           = "BIT_S",
		[SELECTOR_TYPE_BIT_G]           = "BIT_G",
		[SELECTOR_TYPE_BYTE_I]          = "BYTE_I",
		[SELECTOR_TYPE_BYTE_Q]          = "BYTE_Q",
		[SELECTOR_TYPE_BYTE_M]          = "BYTE_M",
		[SELECTOR_TYPE_BYTE_T]          = "BYTE_T",
		[SELECTOR_TYPE_BYTE_SA]         = "BYTE_SA",
		[SELECTOR_TYPE_BYTE_SB]         = "BYTE_SB",
		[SELECTOR_TYPE_BYTE_SC]         = "BYTE_SC",
		[SELECTOR_TYPE_BYTE_S]          = "BYTE_S",
		[SELECTOR_TYPE_BYTE_G]          = "BYTE_G",
		[SELECTOR_TYPE_WORD_AI]         = "WORD_AI",
		[SELECTOR_TYPE_WORD_AQ]         = "WORD_AQ",
		[SELECTOR_TYPE_WORD_R]          = "WORD_R",
	}


    -- 
	-- Protocol object creation and setup
	-- 
    local p_gafanuc_srtp = Proto("GE-SRTP", "GE-FANUC - Service Request Transfer Protocol")

  	-- preferences
	p_gafanuc_srtp.prefs["tcp_ports"] = Pref.range("TCP Ports", _F("%d", DEFAULT_GESRTP_PORT), _F("TCP ports the dissector should be registered for (default: %d", DEFAULT_GESRTP_PORT), 65535)

    -- 
	-- protocol fields
	--
	local fields = p_gafanuc_srtp.fields

    fields.pkt_type       = ProtoField.uint16("gesrtp.pkt_type",       "Packet Type",            base.DEC)
	fields.index          = ProtoField.uint16("gesrtp.index",          "Sequence #",             base.DEC)
	fields.size           = ProtoField.uint16("gesrtp.size",           "Text Length",            base.DEC)
	fields.unknown        = ProtoField.bytes ("gesrtp.unknown",        "Unknown Fields",         base.SPACE)
	fields.unknown_u8     = ProtoField.uint8 ("gesrtp.unknown.u8",     "Unknown Field (uint8)",  base.HEX_DEC)
	fields.unknown_u16    = ProtoField.uint16("gesrtp.unknown.u16",    "Unknown Field (uint16)", base.HEX_DEC)
	fields.unknown_u24	  = ProtoField.uint24("gesrtp.unknown.u24",    "Unknown Field (uint24)", base.HEX_DEC)
	fields.unknown_u32	  = ProtoField.uint32("gesrtp.unknown.u32",    "Unknown Field (uint32)", base.HEX_DEC)
	fields.time           = ProtoField.bytes ("gesrtp.time",           "Time",                   base.SPACE)
	    fields.time_ss    = ProtoField.uint8 ("gesrtp.time.sec",       _F("%-6s", "Second"),     base.DEC)
	    fields.time_mm    = ProtoField.uint8 ("gesrtp.time.min",       _F("%-6s", "Minute"),     base.DEC)
	    fields.time_hh    = ProtoField.uint8 ("gesrtp.time.hour",      _F("%-6s", "Hour"),       base.DEC)
	    fields.time_rsv   = ProtoField.uint8 ("gesrtp.time.reserved",  "Reserved",               base.HEX)
 
    fields.msg_seq        = ProtoField.uint8 ("gesrtp.msg_seq",       "Sequence Number",         base.DEC)
	fields.msg_type       = ProtoField.uint8 ("gesrtp.msg_type",      "Message Type",            base.HEX_DEC)
	fields.mbox_src       = ProtoField.uint32("gesrtp.mbox_src",      "Mailbox Source",          base.HEX)
	fields.mbox_dst       = ProtoField.uint32("gesrtp.mbox_dst",      "Mailbox Destination",     base.HEX)
	fields.pkt_num        = ProtoField.uint8 ("gesrtp.pkt_num",       "Packet #",                base.DEC)
	fields.total_pkt_num  = ProtoField.uint8 ("gesrtp.total_pkt_num", "Total Packet #",          base.DEC)
	fields.svc_req_code   = ProtoField.uint8 ("gesrtp.svc_req_code",  "Service Request Code",    base.HEX)
	fields.seg_selector   = ProtoField.uint8 ("gesrtp.seq_selector",  "Segment Selector",        base.HEX)

	fields.extended		  = ProtoField.bytes ("gesrtp.extended",      "Extended",                base.SPACE)
  
	fields.target_index   = ProtoField.uint16("gesrtp.target.index",  "Target Index",            base.DEC_HEX)
	fields.target_count   = ProtoField.uint16("gesrtp.target.count",  "Target Count",            base.DEC)
  
	fields.payload        = ProtoField.bytes ("gertsp.payload",       "Payload",                 base.SPACE)

	local function parse(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		local pkt_type =                buf(offset_ +  0, 2):le_uint()
		lt:add_le(fields.pkt_type,      buf(offset_ +  0, 2))  -- Packet Type
			:append_text(_F(" [%s]", pkt_type_str[pkt_type])) 
			
		lt:add_le(fields.index,         buf(offset_ +  2, 2))  -- Sequence #
		lt:add_le(fields.size,          buf(offset_ +  4, 2))  -- Text Length

		local ut = lt:add(fields.unknown,           buf(offset_ +  6, 20))
		ut:add_le(fields.unknown_u16,     buf(offset_ +  6, 2))
		ut:add_le(fields.unknown_u32,     buf(offset_ +  8, 4))
		ut:add_le(fields.unknown_u32,     buf(offset_ + 12, 4))
		ut:add_le(fields.unknown_u32,     buf(offset_ + 16, 4))
		ut:add_le(fields.unknown_u32,     buf(offset_ + 20, 4))
		ut:add_le(fields.unknown_u16,     buf(offset_ + 24, 2))

		local time_tree = 
		    lt:add(fields.time,         buf(offset_ + 26, 3))  -- Time
		    	:append_text(_F(" [%02d:%02d:%02d]", 
					buf(offset_ + 26 + 2, 1):uint(),  -- Hour
					buf(offset_ + 26 + 1, 1):uint(),  -- Minute
					buf(offset_ + 26 + 0, 1):uint())) -- Second
		time_tree:add_le(fields.time_hh,  buf(offset_ + 26 + 2, 1))
		time_tree:add_le(fields.time_mm,  buf(offset_ + 26 + 1, 1))
		time_tree:add_le(fields.time_ss,  buf(offset_ + 26 + 0, 1))

		lt:add_le(fields.unknown_u8,    buf(offset_ + 29, 1)) -- reserved

		local msg_type =                buf(offset_ + 31, 1):uint()
		lt:add_le(fields.msg_seq,       buf(offset_ + 30, 1)) -- Msg Seq #
		lt:add_le(fields.msg_type,      buf(offset_ + 31, 1)) -- Msg Type
			:append_text(_F(" [%s]", msg_type_str[msg_type]))
		lt:add_le(fields.mbox_src,      buf(offset_ + 32, 4)) -- Mailbox Src
		lt:add_le(fields.mbox_dst,      buf(offset_ + 36, 4)) -- Mailbox Dest

		lt:add_le(fields.pkt_num,       buf(offset_ + 40, 1)) -- Packet #
		lt:add_le(fields.total_pkt_num, buf(offset_ + 41, 1)) -- Total Packet #

		if     (msg_type == MSG_TYPE_SHORT) then

			local svc_req_code =            buf(offset_ + 42, 1):uint()
			lt:add_le(fields.svc_req_code,  buf(offset_ + 42, 1)) -- Service Request Code
				:append_text(_F(" [%s]", svc_type_str[svc_req_code]))
			local seq_selector =            buf(offset_ + 43, 1):uint()
			lt:add_le(fields.seg_selector,  buf(offset_ + 43, 1)) -- Segment Selector
				:append_text(_F(" [%s]", selector_type_str[seq_selector]))

			lt:add_le(fields.target_index,  buf(offset_ + 44, 2)) -- Index
			lt:add_le(fields.target_count,  buf(offset_ + 46, 2)) -- Count
			lt:add_le(fields.payload,       buf(offset_ + 48, 6)) -- Inline payload

			lt:add_le(fields.unknown_u16,   buf(offset_ + 54, 2))

		elseif (msg_type == MSG_TYPE_SHORT_ACK) then

			lt:add_le(fields.unknown_u16,   buf(offset_ + 42, 2))

			lt:add_le(fields.payload,       buf(offset_ + 44, 6)) -- Inline payload

			lt:add_le(fields.unknown_u32,   buf(offset_ + 50, 4))
			lt:add_le(fields.unknown_u16,   buf(offset_ + 54, 2))

		elseif (msg_type == MSG_TYPE_EXTENDED) then

			local ut1 = lt:add_le(fields.unknown, buf(offset_ + 42, 6))
			ut1:add_le(fields.unknown_u16,   buf(offset_ + 42, 2))
			ut1:add_le(fields.unknown_u32,   buf(offset_ + 44, 4))

			lt:add_le(fields.pkt_num,       buf(offset_ + 48, 1)) -- Packet #
			lt:add_le(fields.total_pkt_num, buf(offset_ + 49, 1)) -- Total Packet #

			local svc_req_code =            buf(offset_ + 50, 1):uint()
			lt:add_le(fields.svc_req_code,  buf(offset_ + 50, 1)) -- Service Request Code
				:append_text(_F(" [%s]", svc_type_str[svc_req_code]))
			local seq_selector =            buf(offset_ + 51, 1):uint()
			lt:add_le(fields.seg_selector,  buf(offset_ + 51, 1)) -- Segment Selector
				:append_text(_F(" [%s]", selector_type_str[seq_selector]))

			lt:add_le(fields.target_index,  buf(offset_ + 52, 2))
			lt:add_le(fields.target_count,  buf(offset_ + 54, 2))

		elseif (msg_type == MSG_TYPE_EXTENDED_ACK) then

			local ut1 = lt:add_le(fields.unknown, buf(offset_ + 42, 6))
			ut1:add_le(fields.unknown_u16,   buf(offset_ + 42, 2))
			ut1:add_le(fields.unknown_u32,   buf(offset_ + 44, 4))

			lt:add_le(fields.pkt_num,       buf(offset_ + 48, 1)) -- Packet #
			lt:add_le(fields.total_pkt_num, buf(offset_ + 49, 1)) -- Total Packet #

			local svc_req_code =            buf(offset_ + 50, 1):uint()
			lt:add_le(fields.svc_req_code,  buf(offset_ + 50, 1)) -- Service Request Code
				:append_text(_F(" [%s]", svc_type_str[svc_req_code]))
			local seq_selector =            buf(offset_ + 51, 1):uint()
			lt:add_le(fields.seg_selector,  buf(offset_ + 51, 1)) -- Segment Selector
				:append_text(_F(" [%s]", selector_type_str[seq_selector]))

			local ut2 = lt:add_le(fields.unknown, buf(offset_ + 52, 4))
			ut2:add_le(fields.unknown_u16,   buf(offset_ + 52, 2))
			ut2:add_le(fields.unknown_u16,   buf(offset_ + 54, 2))

		end

		offset_ = offset_ + 56

		return (offset_ - offset)
	end

	-- actual dissector method
	function p_gafanuc_srtp.dissector(buf, pkt, tree)
		local buf_len = buf:len()
		if (buf_len < 56) then return end

		local offset = pkt.desegment_offset or 0
		print(p_gafanuc_srtp.name .. ": offset = " .. offset)
		


		local pkt_len = buf_len

		-- add protocol to tree
		local prot_tree = tree:add(p_gafanuc_srtp, buf(offset, pkt_len - offset))

		-- add info to top pkt view
		pkt.cols.protocol = p_gafanuc_srtp.name

		-- dissect pkt
		local res = parse(buf, pkt, prot_tree, offset)

		if (buf_len > 56) then
			prot_tree:add(fields.payload, buf(56, pkt_len - res))
		end
	end


	-- init routine
	function p_gafanuc_srtp.init()
		local tcp_dissector_table = DissectorTable.get("tcp.port")
		tcp_dissector_table:add(p_gafanuc_srtp.prefs.tcp_ports, p_gafanuc_srtp)
	end
end