-- OpenContrail vRouter implementation in user space
module(..., package.seeall)

local ffi = require("ffi")

local pcap = require("apps.pcap.pcap")
local raw = require("apps.socket.raw")

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


-- vRouter App with simple forwarding

vRouter = {}

function vRouter:new(conf)
	local rtable = conf.ip_addresses
	local mtable = conf.mac_addresses
	return setmetatable({ rtable = rtable, mtable=mtable }, { __index = vRouter }) 
end

local function get_ipv4_proto(ptr)
   return ptr[9]
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

			if(get_ipv4_proto(ipv4_pkt) == 1) then
				cidr = addr .. "/24";
				ip,mask = getIPAndMask(cidr);

				longest_index = longestPrefixMatch(self.rtable,ip);
				
				print("Source IP " .. src_addr .. " Packet for address " .. addr);
				print("Routing table index " .. longest_index);

				---[[
				local newMAC  = self.mtable[longest_index];
			
				ffi.copy(pkt.data, ethernet:pton(newMAC),6);

				--for _,port in ipairs(self.output) do
					--transmit(port,pkt);
				--end

				--]]
			
				if( self.output[tostring(longest_index)] ~= nil) then 
					transmit(self.output[tostring(longest_index)], pkt)
					ffi.cdef[[
					     int clock_gettime(clockid_t clk_id, struct timespec *tp);
					     int snprintf ( char * s, size_t n, const char * format, ... );
				    		]]
					local buf = ffi.new("struct timespec")
				    	ffi.C.clock_gettime(0,buf);
				    	--print(buf);
				end

				--[[for i=1,#self.rtable do
					if(self.rtable[i]==addr) then
						break;				
					end
				end
				--]]
			
				--packet.free(pkt);
			end
		end
	end
end


function reverse (arr)
	local i, j = 1, #arr;

	while i < j do
		arr[i], arr[j] = arr[j], arr[i];

		i = i + 1;
		j = j - 1;
	end
end

function getIPAndMask(cidr)
	ip,_,subnet = string.match(cidr,"([^/]+)(/)([^/]+)");

	ip_bits = { {0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0} };

	mask = {};

	for i=1,tonumber(subnet) do
		mask[i]=1;
	end

	for i=tonumber(subnet)+1,32 do
		mask[i]=0;
	end

	local k=1;
	local j=1;
	for i in string.gmatch(ip,"[^.]+") do
		curr = tonumber(i);
		k=1;
		while curr>=1 do
			ip_bits[j][k]=curr%2;
			curr=math.floor(curr/2);
			k=k+1;
		end

		reverse(ip_bits[j]);	
		j=j+1;
	end

	return ip_bits,mask;
end

function getMaskNumberFromIpString(cidr)
	ip,_,subnet = string.match(cidr,"([^/]+)(/)([^/]+)");
	return subnet;
end 

function printIPAndMask(ip, mask)
	for i=1,4 do
		for j=1,#ip[i] do
			io.write(ip[i][j]);
		end
		io.write(" ");
	end

	print("");

	for j=1,#mask do
		io.write(mask[j]);
	end
	
	print("");

end

-- this is because I couldnt install the bitop library
function bitAnd(b1, b2)
	if(b1==1 and b2==1) then
		return 1;
	end


	return 0;

end

function getNetworkId(ip,mask)
	k=1;

	result={};

	for i=1,4 do
		for j=1,#ip[i] do
			result[k]=bitAnd(tonumber(ip[i][j]),tonumber(mask[k]));
			k=k+1
		end
	end

	return result;
end

function matchPrefix(base, new,max)
	i=1;
	j=1;
	max = tonumber(max);

	prefixLength=0;

	while(i<=#base and j<=#new and prefixLength<max) do
		if(base[i]~=new[j]) then
			break;
		end
		i=i+1;
		j=j+1;
		prefixLength=prefixLength+1;
	end

	--print("end");

	if(prefixLength<max) then
		return -1;
	end

	return prefixLength;
end

function concatenateIP(ip)
	k=1;
	result = {}
	
	for i=1,4 do
		for j=1,8 do
			result[k]=ip[i][j];
			k=k+1;
		end
	end
	return result;
end

function longestPrefixMatch(ipAddresses, destNetwork)
	longest=0;
	longest_index=0;

	for i=1,#ipAddresses do
		ip,mask  = getIPAndMask(ipAddresses[i]);

		currentNetwork = getNetworkId(destNetwork,mask);
		
		currentPrefix = matchPrefix(currentNetwork,concatenateIP(ip),getMaskNumberFromIpString(ipAddresses[i]));
		if(currentPrefix>longest) then
			longest=currentPrefix;
			longest_index=i;	
		end
	end

	return longest_index;
end


function run(parameters)
	local c = config.new()

	local arr_ip = {"192.168.45.0/24","192.168.1.130/25","192.168.7.0/24","192.168.1.0/24","192.168.0.0/24","192.168.3.0/24","192.168.6.0/24","192.168.4.0/24","192.168.2.0/27","192.168.10.0/26"}

	local arr_mac = {"08:00:27:24:3b:8d","08:00:27:24:3b:8d","08:00:27:24:3b:8d","08:00:27:89:28:d6","08:00:27:e4:33:48","08:00:27:24:3b:8d","08:00:27:24:3b:8d","08:00:27:24:3b:8d","08:00:27:24:3b:8d","08:00:27:24:3b:8d"}

	local i_faces = { "veth2","veth1" } 

	for i = 1,10 do
		table.insert(arr_ip, arr_ip[i])
		config.app(c, "playback"..tostring(i), raw.RawSocket, i_faces[(i%2)+1]);
			
	end


	local pcap_file = parameters[1]

	--config.app(c, "capture", pcap.PcapReader, pcap_file)
	config.app(c, "vInput", raw.RawSocket, "veth0")
	
	config.app(c, "vRouter", vRouter, { ip_addresses = arr_ip, mac_addresses=arr_mac })
	
	config.link(c, "vInput.tx -> vRouter.input")
	--config.link(c, "capture.output -> vRouter.input")

	for i = 1,10 do
		config.link(c, "vRouter." .. tostring(i) .. " -> " .. "playback" .. tostring(i) .. ".rx")
	end

	engine.configure(c)

	engine.main({ duration = 1000 , report = { showlinks = true } })
end
