-- OpenContrail vRouter implementation in user space
module(..., package.seeall)

local ffi = require("ffi")

local pcap = require("apps.pcap.pcap")
local raw = require("apps.socket.raw")

local link = require("core.link")
local packet = require("core.packet")
local lib = require("core.lib")

local transmit, receive = link.transmit, link.receive


reciever = {}

function reciever:new()
	return setmetatable({},{ __index = reciever }) 
end

function reciever:push()
	local input = self.input.input
	if input then
		for _ = 1, link.nreadable(input) do
					local pkt = receive(input)
					ffi.cdef[[
						int clock_gettime(clockid_t clk_id, struct timespec *tp);
						int snprintf ( char * s, size_t n, const char * format, ... );
						]]

					local buf = ffi.new("struct timespec")
				    	ffi.C.clock_gettime(0,buf);
				    	print(buf);
					packet.free(pkt)
		end
	end
end

function run(parameters)
	local c = config.new()

	local iface = "veth0" 

	config.app(c, "vInput", raw.RawSocket, iface)
	
	config.app(c, "reciever", reciever)
	
	config.link(c, "vInput.tx -> reciever.input")

	engine.configure(c)

	engine.main({ duration = 1000 , report = { showlinks = true } })
end
