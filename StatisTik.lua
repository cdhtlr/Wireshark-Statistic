-- ================================================================================ --
-- DO NOT REMOVE CREDIT and COMMENT                                                 --
-- Made by Sidik Hadi Kurniadi                                                      --
-- ================================================================================ --
-- This is a very simple script to simplify Wireshark statistic                     --
-- ================================================================================ --
-- How to use : wireshark -X lua_script:StatisTik.lua                               --
-- or                                                                               --
-- Open a pcap file in wireshark, and then select 'TOOLS/StatisTik --
-- ================================================================================ --

ip_len_f = Field.new ("ip.len")
time_relative_f = Field.new ("frame.time_relative")
time_delta_displayed_f = Field.new ("frame.time_delta_displayed")
default_filter = "!(icmp.type eq 3 || icmp.type eq 4 || icmp.type eq 5 || icmp.type eq 11 || icmpv6.type eq 1 || icmpv6.type eq 2 || icmpv6.type eq 3 || icmpv6.type eq 4)"

-- main function
function StatisTik()
   -- statistic function
   function create_stat(filter)
      local results = {
         -- Total
         ["counter"] = 0,
		 ["framelength"] = 0,
		 ["timerelative"] = 0,
         ["badtcp"] = 0,
		 ----------------------
         ["lostsmt"] = 0,
         ["acklostsmt"] = 0,
         ["dupack"] = 0,
         ["retrans"] = 0,
         ["fastretrans"] = 0,
         ----------------------
		 ["outorder"] = 0,
		 ----------------------
         ["windowfull"] = 0,
         ["zerowindow"] = 0,
         ["zerowindowprobe"] = 0,
         ["zerowindowprobeack"] = 0,
		 ----------------------
         ["avgdelay"] = 0,
         ["idle"] = 0,
         ["avgpps"] = 0,
         ["avgpsize"] = 0,
         ["packetloss"] = 0,
         ["badtcppct"] = 0,
         ["throughput"] = 0,
         ["jitter"] = 0,
      }
      local result_win = TextWindow.new("StatisTik")

      -- called by tap.draw
      function refresh_result()
         result_win:clear()
         result_win:set("Filter:\t " .. filter .. "\n")
         result_win:append("\nTotal\n")
         result_win:append("\tTotal Packets:\t\t " .. results["counter"] .. "\n")
         result_win:append("\tTotal Frame Length:\t " .. results["framelength"] .. " Byte(s)\n")
         result_win:append("\tTotal Time:\t\t " .. results["timerelative"] .. " second(s)\n")
         result_win:append("\nBad TCP:\t\t\t " .. results["badtcp"] .. "\n")
         ----------------------
		 result_win:append("\tLost Segment:\t\t " .. results["lostsmt"] .. "\n")
         result_win:append("\tACK Lost Segment:\t " .. results["acklostsmt"] .. "\n")
		 result_win:append("\tDuplicate ACK:\t\t " .. results["dupack"] .. "\n")
         result_win:append("\tRetransmission:\t\t " .. results["retrans"] .. " (Fast Retransmission: " .. results["fastretrans"] .. ")\n")
         ----------------------
		 result_win:append("\tOut of Order:\t\t " .. results["outorder"] .. "\n")
		 ----------------------
         result_win:append("\tWindow Full:\t\t " .. results["windowfull"] .. "\n")
		 result_win:append("\tZero Window:\t\t " .. results["zerowindow"] .. "\n")
		 result_win:append("\tZero Window Probe:\t " .. results["zerowindowprobe"] .. "\n")
		 result_win:append("\tZero Window Probe ACK:\t " .. results["zerowindowprobeack"] .. "\n\n")
		 ----------------------
         result_win:append("Avg Delay:\t\t " .. results["avgdelay"] .. " second/packet\n")
         result_win:append("Idle Time:\t\t " .. results["idle"] .. " second(s)\n")
		 result_win:append("Jitter:\t\t\t " .. results["jitter"] .. " second/packet\n\n")
         result_win:append("Avg Packets/second:\t " .. results["avgpps"] .. " packets/second\n")
         result_win:append("Avg Packet Size:\t " .. results["avgpsize"] .. " Byte(s)\n")
		 result_win:append("Current Throughput:\t " .. results["throughput"] .. " kilobits/second\n\n")
		 result_win:append("Bad TCP Percentage:\t " .. results["badtcppct"] .. " % (" .. results["packetloss"] ..  "% packet loss of Total Packets)\n")
      end
	  
	  -- lost segment, total
      local lostsmt_tap = Listener.new("frame", "tcp.analysis.lost_segment && " .. default_filter .. " && " .. filter)
      function lostsmt_tap.packet(pinfo, tvb, ip)
         results["lostsmt"] = results["lostsmt"] + 1
      end

      -- ack lost segment, total
      local acklostsmt_tap = Listener.new("frame", "tcp.analysis.ack_lost_segment && " .. default_filter .. " && " .. filter)
      function acklostsmt_tap.packet(pinfo, tvb, ip)
         results["acklostsmt"] = results["acklostsmt"] + 1
      end
	  
	  -- dupack, total
      local dupack_tap = Listener.new("frame", "tcp.analysis.duplicate_ack && " .. default_filter .. " && " .. filter)
      function dupack_tap.packet(pinfo, tvb, ip)
         results["dupack"] = results["dupack"] + 1
      end
	  
	  -- retransmission, total
      local retrans_tap = Listener.new("frame", "tcp.analysis.retransmission && " .. default_filter .. " && " .. filter)
      function retrans_tap.packet(pinfo, tvb, ip)
         results["retrans"] = results["retrans"] + 1
      end

      -- fast retransmission, total
      local fastretrans_tap = Listener.new("frame", "tcp.analysis.fast_retransmission && " .. default_filter .. " && " .. filter)
      function fastretrans_tap.packet(pinfo, tvb, ip)
         results["fastretrans"] = results["fastretrans"] + 1
      end
	  
	  -- outorder, total
      local outorder_tap = Listener.new("frame", "tcp.analysis.out_of_order && " .. default_filter .. " && " .. filter)
      function outorder_tap.packet(pinfo, tvb, ip)
         results["outorder"] = results["outorder"] + 1
      end

	  -- window full, total
      local windowfull_tap = Listener.new("frame", "tcp.analysis.window_full && " .. default_filter .. " && " .. filter)
      function windowfull_tap.packet(pinfo, tvb, ip)
         results["windowfull"] = results["windowfull"] + 1
      end
	  
      -- zero window, total
      local zerowindow_tap = Listener.new("frame", "tcp.analysis.zero_window && " .. default_filter .. " && " .. filter)
      function zerowindow_tap.packet(pinfo, tvb, ip)
         results["zerowindow"] = results["zerowindow"] + 1
      end
	  
	  -- zero window probe, total
      local zerowindowprobe_tap = Listener.new("frame", "tcp.analysis.zero_window_probe && " .. default_filter .. " && " .. filter)
      function zerowindowprobe_tap.packet(pinfo, tvb, ip)
         results["zerowindowprobe"] = results["zerowindowprobe"] + 1
      end
	  
	  -- zero window probe ack, total
      local zerowindowprobeack_tap = Listener.new("frame", "tcp.analysis.zero_window_probe_ack && " .. default_filter .. " && " .. filter)
      function zerowindowprobeack_tap.packet(pinfo, tvb, ip)
         results["zerowindowprobeack"] = results["zerowindowprobeack"] + 1
      end

	  -- packets counter, total
      local counter_tap = Listener.new("frame", "" .. default_filter .. " && " .. filter)
	  function counter_tap.reset()
         results["counter"] = 0
         results["framelength"] = 0
         results["timerelative"] = 0
         results["badtcp"] = 0
		 ----------------------
         results["lostsmt"] = 0
         results["acklostsmt"] = 0
         results["dupack"] = 0
         results["retrans"] = 0
         results["fastretrans"] = 0
         ----------------------
		 results["outorder"] = 0
		 ----------------------
         results["windowfull"] = 0
         results["zerowindow"] = 0
         results["zerowindowprobe"] = 0
         results["zerowindowprobeack"] = 0
		 ----------------------
		 results["avgdelay"] = 0
		 results["idle"] = 0
		 results["avgpps"] = 0
		 results["avgpsize"] = 0
		 results["packetloss"] = 0
		 results["badtcppct"] = 0
		 results["throughput"] = 0
		 results["jitter"] = 0
      end
      function counter_tap.packet(pinfo, tvb, ip)
         results["counter"] = results["counter"] + 1
		 local ip_len = 0
		 local time_relative = time_relative_f()
		 local time_delta_displayed = time_delta_displayed_f()
		 local eth_header = 14
 		 local ip_lengths = {ip_len_f()}
		 for i,ip_length in ipairs (ip_lengths) do
			ip_len = ip_length.value + eth_header
		 end
		 results["framelength"] = results["framelength"] + ip_len
		 results["timerelative"] = time_relative().secs	 
		 results["badtcp"] = (results["lostsmt"]+results["acklostsmt"]+results["dupack"]+results["retrans"]+results["fastretrans"]+results["outorder"]+results["windowfull"]+results["zerowindow"]+results["zerowindowprobe"]+results["zerowindowprobeack"])
		 results["avgdelay"] = (results["timerelative"]/results["counter"])
		 results["avgpps"] = (results["counter"]/results["timerelative"])
		 results["avgpsize"] = (results["framelength"]/results["counter"])
		 results["packetloss"] = (results["lostsmt"]/results["counter"])*100
		 results["badtcppct"] = (results["badtcp"]/results["counter"])*100
		 results["throughput"] = (results["framelength"]/results["timerelative"])*8/1024
		 results["jitter"] = (results["timerelative"]-(results["throughput"]/1024))/results["counter"]
		 if (time_delta_displayed().secs > results["idle"])
			then results["idle"] = time_delta_displayed().secs
		 end
      end
      function counter_tap.draw()
         refresh_result()
      end
	  
      function remove_alltap()
         counter_tap:remove()
		 ----------------------
         lostsmt_tap:remove()
         acklostsmt_tap:remove()
		 dupack_tap:remove()
         retrans_tap:remove()
         fastretrans_tap:remove()
		 ----------------------
		 outorder_tap:remove()
		 ----------------------
		 windowfull_tap:remove()
         zerowindow_tap:remove()
         zerowindowprobe_tap:remove()
         zerowindowprobeack_tap:remove()
      end

      result_win:set_atclose(remove_alltap)
      
      -- retap all the packets, then all the listeners begin to work.
      retap_packets()
      
   end

   -- Prompt for filter
   new_dialog("Please input filter", create_stat, "Filter:")
end

-- register the menu
register_menu("StatisTik", StatisTik, MENU_TOOLS_UNSORTED)
