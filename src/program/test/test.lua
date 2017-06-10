-- OpenContrail vRouter implementation in user space
module(..., package.seeall)

local pcap = require("apps.pcap.pcap")

local ffi = require("ffi")
local bit = require("bit")

local ethernet = require("lib.protocol.ethernet")
local datagram = require("lib.protocol.datagram")
local ipv4 = require("lib.protocol.ipv4")

local link = require("core.link")
local packet = require("core.packet")
local lib = require("core.lib")

local raw = require("apps.socket.raw")

local lwutil = require("apps.lwaftr.lwutil")
local lwtypes = require("apps.lwaftr.lwtypes")

local transmit, receive = link.transmit, link.receive
local rd16, rd32, wr16 = lwutil.rd16, lwutil.rd32, lwutil.wr16
local ethernet_header_ptr_type = lwtypes.ethernet_header_ptr_type
local cast = ffi.cast
local band, bor, bxor = bit.band, bit.bor, bit.bxor

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

local function printx(num)
  print("0x" .. num)
end

local function get_ip_address_as_string(addr)
	local address = (addr[0] .. "." .. addr[1] .. "." .. addr[2] .. "." .. addr[3])
	return address 
end

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

-- Global Variables

local iface_id        = 1
local h_id            = 1
local label           = 100


-- VM app

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
	local count = 0

	local config = {
		--mac_address = mac_address,
		ipv4_address = ipv4_address,
		dst_ipv4_address = dst_ipv4_address,
		count = count
	}

	--print("self " .. ipv4:ntop(config.ipv4_address))
	--print("dst" .. ipv4:ntop(config.dst_ipv4_address))
	return setmetatable(config, { __index = VM })
end

-- Function to capture packets from network
-- This function also check if the packet is destined for given
-- Virtual Machine and accepts if it is otherwise drops.
function VM:push()
	local input = self.input.input

	if input then
		for _ = 1, link.nreadable(input) do
			local pkt = receive(input)
			self.count = self.count + 1	
			local ipv4_pkt = get_ethernet_payload(pkt)
			local ipv4_src_address = get_ipv4_src_address(ipv4_pkt)
			local src_addr = (ipv4_pkt + 12)[0] .. "." .. (ipv4_pkt + 12)[1] .. "." .. (ipv4_pkt + 12)[2] .. "." .. (ipv4_pkt + 12)[3] .. ""
			local dst_addr = (ipv4_pkt + 16)[0] .. "." .. (ipv4_pkt + 16)[1] .. "." .. (ipv4_pkt + 16)[2] .. "." .. (ipv4_pkt + 16)[3] .. ""
			local s_addr = get_ip_address_as_string(ipv4_pkt + 12)
			
			--print(rd32(ipv4:pton(dst_addr)))
			--print(rd32(self.config.ipv4_address))
			--print("dst - > " .. dst_addr)
			--print("self -> " .. get_ip_address_as_string(self.ipv4_address))
			if get_ethertype(pkt) == n_ethertype_ipv4 then
				if rd32(ipv4:pton(dst_addr)) == rd32(self.ipv4_address) then
					print(("Packet received for IP address: %s"):format(src_addr))
				end
			end 	
		end
	end
	print("Count = " .. self.count)
end

-- Function to insert packets into network
function VM:pull()
	local output = self.output.output

	local new_packet = packet.allocate()
	local dgram = datagram:new(new_packet)
	local ipv4_header = ipv4:new({ ttl = default_ttl,
								   protocol = proto_icmp,
								   src = self.ipv4_address,
								   dst = self.dst_ipv4_address })

	--print("in pull 1 -> " .. ipv4:ntop(self.config.dst_ipv4_address))
	dgram:push(ipv4_header)
	new_packet = dgram:packet()
	ipv4_header:free()
	new_packet = packet.shiftright(new_packet, ethernet_header_size)
	write_eth_header(new_packet.data, from_eth, to_eth, n_ethertype_ipv4)	

	if output then
		for _ = 1, link.nwritable(output) do
			transmit(output, new_packet)
		end	
	end
end



-- vRouter App

vRouter = {
  config = {
    ipv4_address = { required = true },
    mask = { required = true },
    output_port_type = { required = false }
  }
}


-- Fuction for checking if given IP address belongs to the network
-- i.e. check if IP is intranetwork or internetwork
local function get_numeric_mask(bit_count)
	local val = 0
	local exp = 31
	while bit_count > 0 do
		val = val + (2 ^ exp)
		exp = exp - 1
		bit_count = bit_count - 1
	end

	return val
end

local function check_if_ip_belongs_to_network(net_ip, mask, dst_ip)
  print("hey")
  local numeric_dst_ip = rd32(ipv4:pton(dst_ip))
  local numeric_mask = rd32(mask)
  local numeric_net_ip = rd32(net_ip)

  local ans = band(numeric_dst_ip , numeric_mask)
  --printx(bit.tohex(numeric_ip))       -- prints hex value from lsb to msb i.e. in reverse direction
  --printx(bit.tohex(numeric_mask))
  --printx(bit.tohex(ans))

  print(numeric_net_ip == ans)
  return (numeric_net_ip == ans)
end

-- Function for lookup in the Routing table

local function lookup(ipv4_addr)
	
end

-- Function to check if input/output ports are correctly configured

local function ports_valid(ports)
	for port, i in ipairs(ports) do
		if not port then
			return false
		end
	end

	return true
end


-- Configure vRouter

function vRouter:new(conf)
  local ipv4_address = ipv4:pton(conf.ipv4_address)
  local mask  = ipv4:pton(conf.mask)
  
  local o = {
    ipv4_address = ipv4_address,
  	mask = mask
  }

  return setmetatable(o, { __index = vRouter })
end


function vRouter:push()
	local input, output = self.input, self.output

	if input.in1 or input .in2 then
		for i, port in ipairs(input) do
			for _ = 1, link.nreadable(port) do
				local pkt = receive(port)
				local ipv4_pkt = get_ethernet_payload(pkt)
				local dst_ip = get_ipv4_dst_address(ipv4_pkt)
				local str_dst_ip = get_ip_address_as_string(ipv4_pkt + 16)
				io.write("dst ip -> ")
				print(dst_ip)

				local flag = check_if_ip_belongs_to_network(self.ipv4_address, self.mask, str_dst_ip)
				print(flag)
				
				if flag == true then
					local id = tostring(i)
					transmit(output["out" .. i], pkt)
					print("transmitted to out -> " .. id)
				else
					transmit(output.out3, pkt)
					print("transmitted to gateway!!")
				end
			end
		end
	end

end


-- Main function

function run()
  check_if_ip_belongs_to_network(ipv4:pton("192.168.0.8"), ipv4:pton("255.255.255.248"), "192.168.0.10")
  --print(get_numeric_mask(30))


  local c = config.new()

  --config.app("vm1", RawSocket, "tap1")
  --config.app("vm2", RawSocket, "tap2")

  local pcap_file = "/home/suraj/workspace/BEProject/snabb/src/program/example_replay/http_m1.pcap"
  config.app(c, "capture", pcap.PcapReader, pcap_file)



  config.app(c, "vm1", VM, { ipv4_address = "192.168.0.117", dst_ipv4_address = "192.168.0.118"})
  config.app(c, "vm2", VM, { ipv4_address = "192.168.0.118", dst_ipv4_address = "192.168.0.103"})

  config.app(c, "gateway", raw.RawSocket, "veth0")
  
	
  config.app(c, "vRouter", vRouter, { ipv4_address = "192.168.0.116", mask = "255.255.255.252"})

  config.link(c, "capture.output -> vRouter.in1")
  config.link(c, "capture.output -> vRouter.in2")

  config.link(c, "vRouter.out1 -> vm1.input")
  config.link(c, "vRouter.out2 -> vm2.input")
  config.link(c, "vRouter.out3 -> gateway.rx")

  engine.configure(c)
  engine.main({ duration = 0.01 , reports = {showlinks = true} })
end
