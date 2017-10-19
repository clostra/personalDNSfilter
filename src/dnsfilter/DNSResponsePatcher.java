/* 
 PersonalDNSFilter 1.5
 Copyright (C) 2017 Ingo Zenz

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 Find the latest version at http://www.zenz-solutions.de/personaldnsfilter
 Contact:i.z@gmx.net 
 */

package dnsfilter;


import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;

import util.Logger;
import util.LoggerInterface;

public class DNSResponsePatcher {
	
	private static Set FILTER = null;
	private static LoggerInterface TRAFFIC_LOG = null;
	
	private static byte[] ipv4_localhost;
	private static byte[] ipv6_localhost;
	static {
		try {
			ipv4_localhost = InetAddress.getByName("127.0.0.1").getAddress();
			ipv6_localhost = InetAddress.getByName("::1").getAddress();
		} catch (Exception e) {
			Logger.getLogger().logException(e);
		}
	}	
	
	
	public static void init(Set filter, LoggerInterface trafficLogger) {
		FILTER = filter;
		TRAFFIC_LOG = trafficLogger;		
	}
	
	public static byte[] patchResponse(String client, byte[] response, int offs) throws IOException {

		ByteBuffer buf = ByteBuffer.wrap(response,offs,response.length-offs);
		String queryHost="";

		buf.getShort(); // ID
		buf.getShort(); // Flags
		int questCount = buf.getShort();
		int answerCount = buf.getShort();
		buf.getShort(); // auths
		buf.getShort(); // additional

		boolean filter = false;
		
		for (int i = 0; i < questCount; i++) {
			
			queryHost = readDomainName(buf, offs);
			int type = buf.getShort(); // query type
			
			//checking the filter on the answer does not always work due to cname redirects (type 5 responses)
			//therefore we just check the filter on the query host and thus we'll disallow also all cname redirects.
			//This seems to work well - however is not 100% correct!			
			
			if (type == 1 || type == 28)
				filter = filter || filter(queryHost);			
			
			if (TRAFFIC_LOG != null)
				TRAFFIC_LOG.logLine(client+", Q-"+type+", "+queryHost+", "+"<empty>");
			
			buf.getShort(); // query class
		}

		for (int i = 0; i < answerCount; i++) {
			String host = readDomainName(buf,offs);			
			int type = buf.getShort(); // type			
			buf.getShort(); // class
			buf.getInt(); // TTL
			int len = buf.getShort(); // len
					
			if ((type == 1 || type == 28) && filter) {
				// replace ip!
				if (type == 1) // IPV4
					buf.put(ipv4_localhost);
				else if (type == 28) // IPV6
					buf.put(ipv6_localhost);
			} else
				buf.position(buf.position() + len); // go ahead
			
			//log answer
			if (TRAFFIC_LOG != null) {
				byte[] answer = new byte[len];
				String answerStr=null;
				buf.position(buf.position() - len);
				
				if (type == 5)
					answerStr = readDomainName(buf,offs);
				else {
					buf.get(answer);
					
					if (type == 1 || type == 28)
						answerStr = InetAddress.getByAddress(answer).getHostAddress();
					else 
						answerStr = new String(answer);
				}				
				TRAFFIC_LOG.logLine(client+", A-"+type+", "+host+", "+answerStr+", /Length:"+len);				
			}
		}
		return buf.array();
	}

	private static boolean filter(String host) {
		boolean result;
		
		if (FILTER==null)
			result = false;			
		else 
			result = FILTER.contains(host);
		
		if (result == true) 
			Logger.getLogger().logLine("FILTERED:"+host);
		else
			Logger.getLogger().logLine("ALLOWED:"+host);
		
		return result;
	}
	

	private static String readDomainName(ByteBuffer buf, int offs) throws IOException {

		byte[] substr = new byte[64];

		int count = -1;
		String dot = "";
		String result = "";
		int ptrJumpPos = -1;

		while (count != 0) {
			count = buf.get();
			if (count != 0) {
				if ((count & 0xc0) == 0) {
					buf.get(substr, 0, count);
					result = result + dot + new String(substr, 0, count);
					dot = ".";
				} else {// pointer
					buf.position(buf.position() - 1);
					int pointer = offs + (buf.getShort() & 0x3fff);
					if (ptrJumpPos == -1)
						ptrJumpPos = buf.position();
					buf.position(pointer);
				}
			} else {
				if (count == 0 && ptrJumpPos != -1)
					buf.position(ptrJumpPos);
			}
		}
		return result;
	}
	
}

