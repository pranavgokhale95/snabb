module(..., package.seeall)

local pcap = require("apps.pcap.pcap");
local basic = require("apps.basic.basic_apps");

function run (parameters)
	local input_file = "src/program/example_replay/input.pcap";

	local c = config.new();
	config.app(c,"capture",pcap.PcapReader, input_file);
	config.app(c,"repeater",basic.Repeater);
	config.app(c,"writer",pcap.PcapWriter, "src/program/first_app/output.pcap");
	
	config.link(c,"capture.output -> repeater.input");
	config.link(c,"repeater.output -> writer.input");

	engine.configure(c);
	engine.main( {duration=1, report = {showlinks=true}} )
end
	
