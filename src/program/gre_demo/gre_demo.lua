-- OpenContrail vRouter implementation in user space
module(..., package.seeall)

local ffi = require("ffi")

local pcap = require("apps.pcap.pcap")

local ethernet = require("lib.protocol.ethernet")
local datagram = require("lib.protocol.datagram")
local ipv4 = require("lib.protocol.ipv4")

local link = require("core.link")
local packet = require("core.packet")
local lib = require("core.lib")

local lwutil = require("apps.lwaftr.lwutil")
local lwtypes = require("apps.lwaftr.lwtypes")

local transmit, receive = link.transmit, link.receive
local rd16, rd32, wr16 = lwutil.rd16, lwutil.rd32, lwutil.wr16
local ethernet_header_ptr_type = lwtypes.ethernet_header_ptr_type
local cast = ffi.cast

-- Dummy Values
local from_ip = ipv4:pton("192.168.0.2")
local to_ip = ipv4:pton("192.168.0.12")
local from_eth = ethernet:pton("01:02:03:04:05:06")
local to_eth = ethernet:pton("06:05:04:03:02:01")

-- Constants
local ethernet_header_size = 14

local o_ethernet_dst_addr = 0
local o_ethernet_src_addr = 6
local o_ethernet_ethertype = 12

local o_ipv4_checksum = 10
local o_ipv4_src_addr = 12
local o_ipv4_dst_addr = 16

local n_ethertype_ipv4 = 0x0800

local default_ttl = 255

local proto_icmp = 1
local proto_tcp = 6

-- Basic Functions

local function get_ethertype(pkt)
   return rd16(pkt.data + (ethernet_header_size - 2))
end

local function get_ethernet_payload(pkt)
   return pkt.data + ethernet_header_size
end

local function get_ipv4_dst_address(ptr)
   return rd32(ptr + o_ipv4_dst_addr)
end

local function get_ipv4_src_ptr(ptr)
   return ptr + o_ipv4_src_addr
end

local function get_ipv4_src_address(ptr)
   return rd32(get_ipv4_src_ptr(ptr))
end

local function get_ipv4_checksum_ptr (ptr)
   return ptr + o_ipv4_checksum
end

local function copy_ether(dst, src)
   ffi.copy(dst, src, 6)
end

local function copy_ipv4(dst, src)
   ffi.copy(dst, src, 4)
end

function write_eth_header(dst_ptr, ether_src, ether_dst, eth_type)
   local eth_hdr = cast(ethernet_header_ptr_type, dst_ptr)
   eth_hdr.ether_shost = ether_src
   eth_hdr.ether_dhost = ether_dst
   eth_hdr.ether_type = eth_type
end

-- Code for Basic VM app

VM = {
	config = {
		--mac_address = { required = true },
		ipv4_address = { required = true },
		dst_ipv4_address = { required = true }
	}
}

function VM:new(conf)
	--local mac_address = ethernet:pton(conf.mac_address)
	local ipv4_address = ipv4:pton(conf.ipv4_address)
	local dst_ipv4_address = ipv4:pton(conf.dst_ipv4_address)

	local config = {
		--mac_address = mac_address,
		ipv4_address = ipv4_address,
		dst_ipv4_address = dst_ipv4_address
	}

	return setmetatable({config = config}, { __index = VM })
end

function VM:push()
	local input = self.input.input

	if input then
		for _ = 1, link.nreadable(input) do
			local pkt = receive(input)
			local ipv4_pkt = get_ethernet_payload(pkt)
			local dst_ip = get_ipv4_dst_address(ipv4_pkt)
			local src_addr = (ipv4_pkt + 12)[0] .. "." .. (ipv4_pkt + 12)[1] .. "." .. (ipv4_pkt + 12)[2] .. "." .. (ipv4_pkt + 12)[3] .. ""
			local addr = (ipv4_pkt + 16)[0] .. "." .. (ipv4_pkt + 16)[1] .. "." .. (ipv4_pkt + 16)[2] .. "." .. (ipv4_pkt + 16)[3] .. ""
			
			local sr_ip =ipv4:ntop(self.config.ipv4_address)
			--print("curent " .. sr_ip);
			--print("dst " .. addr);

			--print((dst_addr))
			if tostring(addr) == tostring(sr_ip) then
				print(("Packet received for IP address: %s"):format(src_addr))
			else
				packet.free(pkt)
			end 	
		end
	end
end

function VM:pull()
	
	local output = self.output.output

	local new_packet = packet.allocate()
	local dgram = datagram:new(new_packet)
	local ipv4_header = ipv4:new({ ttl = default_ttl,
								   protocol = proto_icmp,
								   src = self.config.ipv4_address,
								   dst = self.config.dst_ipv4_address })

	dgram:push(ipv4_header)
	new_packet = dgram:packet()
	new_packet = packet.shiftright(new_packet, ethernet_header_size)
	write_eth_header(new_packet.data, from_eth, to_eth, n_ethertype_ipv4)	

	local payl = get_ethernet_payload(new_packet)
	local new_dst = (payl + 16)[0] .. "." .. (payl + 16)[1] .. "." .. (payl + 16)[2] .. "." .. (payl + 16)[3] .. "" 
	if output then
		for _ = 1, link.nwritable(output) do
			transmit(output, new_packet)
		end	
	end
end



-- vRouter App with simple forwarding

vRouter = {}

function vRouter:new(conf)
	local rtable = conf.ip_addresses
	return setmetatable({ rtable = rtable }, { __index = vRouter }) 
end

function vRouter:add_entry(ip, link, i)
	table.insert(self.output, i)
	table.insert(self.rtable, {ip, self.output.i})
end

function vRouter:push()
	local input = self.input.input

	
	if input then
		for _ = 1, link.nreadable(input) do
			local pkt = receive(input)
			local ipv4_pkt = get_ethernet_payload(pkt)
			local dst_ip = get_ipv4_dst_address(ipv4_pkt)
			local src_addr = (ipv4_pkt + 12)[0] .. "." .. (ipv4_pkt + 12)[1] .. "." .. (ipv4_pkt + 12)[2] .. "." .. (ipv4_pkt + 12)[3] .. ""
			local addr = (ipv4_pkt + 16)[0] .. "." .. (ipv4_pkt + 16)[1] .. "." .. (ipv4_pkt + 16)[2] .. "." .. (ipv4_pkt + 16)[3] .. ""
			
			--print("src = " .. src_addr)
			--print("recvd" .. addr)	
			--[[
			if(src_addr == "192.168.0.11") then
				print("src  " .. src_addr)
				print("recvd " .. addr)
			end
			--]]


			--if get_ethertype(pkt) == n_ethertype_ipv4 then
				for i,ip in ipairs(self.rtable) do
					--transmit(self.output["4"], pkt)
					if ip == addr then
						transmit(self.output[tostring(i)], pkt)
						break
					end
				end	
			---else
				--packet.free(pkt)
			--end
		end
	end
end


-- Main Function

function run()
	local c = config.new()

	local arr_ip = {}

	for i = 1,10 do
		local ip = "192.168.0." .. i
		table.insert(arr_ip, ip)
		config.app(c, "vm" .. i, VM, { ipv4_address = ip, dst_ipv4_address = "192.168.0." .. (i+1)})
	end

	local pcap_file = "/home/suraj/workspace/BEProject/snabb/src/program/example_replay/http_m1.pcap"

	config.app(c, "vRouter", vRouter, { ip_addresses = arr_ip })
	config.app(c, "capture", pcap.PcapReader, pcap_file)


	config.link(c, "capture.output -> vRouter.input")

	--config.app(c, "vm11", VM, { ipv4_address = "192.168.0.11", dst_ipv4_address = "192.168.0.4" })	
	--config.link(c, "vm11.output -> vRouter.input")	
	
	ffi.cdef[[
    		 int clock_gettime(clockid_t clk_id, struct timespec *tp);
		 int snprintf ( char * s, size_t n, const char * format, ... );
	]]

	local buf = ffi.new("struct timespec")
	ffi.C.clock_gettime(0,buf);
	print(buf);
--    	clock_gettime(CLOCK_REALTIME, &spec);

	--[[
	config.link(c, "vRouter.".. "1" .." -> vm" .. 1 .. ".input")	
	config.link(c, "vRoute".. 2 .." -> vm" .. 2 .. ".input")	
	config.link(c, "vRoute".. 3 .." -> vm" .. 3 .. ".input")	
	config.link(c, "vRoute".. 4 .." -> vm" .. 4 .. ".input")	
	config.link(c, "vRouter.".. 5 .." -> vm" .. 5 .. ".input")	
	config.link(c, "vRoute".. 6 .." -> vm" .. 6 .. ".input")	
	config.link(c, "vRoute".. 7 .." -> vm" .. 7 .. ".input")	
	config.link(c, "vRoute".. 8 .." -> vm" .. 8 .. ".input")	
	config.link(c, "vRoute".. 9 .." -> vm" .. 9 .. ".input")	
	config.link(c, "vRoute".. 10 .." -> vm" .. 10 .. ".input")	
	--]]

	for i = 1,10 do
		config.link(c, "vRouter.".. tostring(i) .." -> vm" .. i .. ".input")
	end

	engine.configure(c)

	engine.main({ duration = 0.00001 , report = { showlinks = true } })
end
