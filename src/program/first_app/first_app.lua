module(..., package.seeall)

local pcap = require("apps.pcap.pcap")
local raw = require("apps.socket.raw")
local packet = require("core.packet")
local link = require("core.link")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local datagram = require("lib.protocol.datagram")
local constants = require("apps.lwaftr.constants")
local ffi = require("ffi")
local lwtypes = require("apps.lwaftr.lwtypes")

local cast = ffi.cast
local ethHeaderSize = constants.ethernet_header_size
local ethernet_header_ptr_type = lwtypes.ethernet_header_ptr_type


function write_eth_header(dst_ptr, ether_src, ether_dst, eth_type)
	local eth_hdr = cast(ethernet_header_ptr_type, dst_ptr)
	eth_hdr.ether_shost = ether_src
	eth_hdr.ether_dhost = ether_dst
	eth_hdr.ether_type = eth_type
end

Sender = {}

function Sender:new()
	local data = {"a"}
	return setmetatable({data = data},{__index=Sender})	
end

function Sender:pull()
	local src_ip = ipv4:pton("192.168.0.11")
	local dest_ip = ipv4:pton("192.168.0.14")
	local src_mac = ethernet:pton("00:00:00:00:00:00")
	local dest_mac = ethernet:pton("00:00:00:00:00:00")
	
	local p = packet.allocate()
	local dgram = datagram:new(p)
	local ipv4_header = ipv4:new({ttl = constants.default_ttl,
	protocol = constants.proto_icmp,
	src = src_ip, dst = dest_ip})
	dgram:push(ipv4_header)
	p = dgram:packet()
	ipv4_header:free()
	p = packet.shiftright(p, ethHeaderSize)
	write_eth_header(p.data, src_mac, dest_mac, constants.n_ethertype_ipv4)	 
	
	link.transmit(self.output.output , p)			
end

Receiver = {}

function Receiver:new()
	local data = {"a"}
	return setmetatable( {packets = {}}, { __index=Receiver}) 
end

function Receiver:push()
	local l = self.input.input
	if not link.empty(l) then
		local p = link.receive(l)
		table.insert(self.packets,p);
	end
end

function Receiver:pull()
	local npackets = #self.packets;
	local p = self.packets[1];
	if p then 		
		link.transmit(self.output.output,p);
	end
end

function run (parameters)
	if not (#parameters == 1) then
		print("Usage: first_app <interface>")
		main.exit(1)
	end

	local interface = parameters[1]

	print (parse_cidr_ipv4("192.168.15.15/32"));
	local c = config.new()
	config.app(c, "sender", Sender)
	config.app(c, "playback", raw.RawSocket, interface)
	config.app(c, "receiver",Receiver);

	config.link(c, "sender.output -> receiver.input")
	config.link(c, "receiver.output -> playback.rx");
	engine.configure(c)
	engine.main({duration=0.01, report = {showlinks=true}})
end

function parse_cidr_ipv4 (cidr)
	local address, prefix_size =  string.match(cidr, "^(.+)/(%d+)$")
	if not ( address and prefix_size ) then
		return false, "malformed IPv4 CIDR: " .. tostring(cidr)
	end
	prefix_size = tonumber(prefix_size)
	if prefix_size > 32 then
		return false, "IPv6 CIDR mask is too big: " .. prefix_size
	end
	if prefix_size == 0 then
		return true -- any IP
	end
	local in_addr  = ffi.new("int32_t[1]")
	local AF_INET = 2;
	local result = ffi.C.inet_pton(AF_INET, address, in_addr)
	if result ~= 1 then
		return false, "malformed IPv4 address: " .. address
	end
	if prefix_size == 32 then
		-- single IP address
		return true, in_addr[0]
	end
	local mask = bit.bswap(bit.bnot(bit.rshift(bit.bnot(0), prefix_size)))
	print (in_addr[0]);
	return true, bit.band(in_addr[0], mask), mask
end
