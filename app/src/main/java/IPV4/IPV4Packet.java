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

package IPV4;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Arrays;

public class IPV4Packet {

	static short curID = (short) (Math.random()*Short.MAX_VALUE);
	static Object ID_SYNC = new Object();
	
	protected IntBuffer ipHeader;
	
	protected int len; // number of bytes of complete IP Packet (header plus data)!
	protected int offset;
	protected byte[] data;

	public IPV4Packet(byte[] packet, int offs, int len) {
		data = packet;
		offset = offs;
		this.len = len;		
		this.ipHeader=ByteBuffer.wrap(packet,offs, 20).order(ByteOrder.BIG_ENDIAN).asIntBuffer();		
	}	
	

	public static int ip2int(InetAddress ip) {
		byte[] b = ip.getAddress();
		return b[3] & 0xFF | (b[2] & 0xFF) << 8 | (b[1] & 0xFF) << 16 | (b[0] & 0xFF) << 24;
	}

	public static InetAddress int2ip(int ip) throws UnknownHostException {
		byte[] b = new byte[] { (byte) ((ip >> 24) & 0xFF), (byte) ((ip >> 16) & 0xFF), (byte) ((ip >> 8) & 0xFF), (byte) (ip & 0xFF) };
		return InetAddress.getByAddress(b);

	}

	private static int generateId() {
		synchronized (ID_SYNC) {
			curID++;
			return ((int) curID) <<16;
		}
	}
	

	private int calculateCheckSum() {
		return CheckSum.chkSum(data, offset, 20);		
	}
	
	public int checkCheckSum() {
		return calculateCheckSum();
	}

	public void updateHeader(int TTL, int prot, int sourceIP, int destIP) {
		int[] hdrPacket = new int[5];
		hdrPacket[0] = 0x45000000 + len; // Version 4, IP header len (20 bytes /4 = 5), normal TOS (0) + complete pack length in bytes
		hdrPacket[1] = generateId(); // packet ID, fragmentation flags "0" and no fragmentation offset (0)
		hdrPacket[2] = (TTL << 24) + (prot << 16);
		hdrPacket[3] = sourceIP;
		hdrPacket[4] = destIP;
		ipHeader.position(0);
		ipHeader.put(hdrPacket);
		// add checksum
		hdrPacket[2] = hdrPacket[2] + calculateCheckSum();
		ipHeader.put(2, hdrPacket[2]);
		
	}

	public int getSourceIP() {
		return ipHeader.get(3);
	}

	public int getDestIP() {
		return ipHeader.get(4);
	}

	public int getTTL() {
		return ipHeader.get(2) >>> 24;
	}

	public int getProt() {
		return ipHeader.get(2) >>> 16 & 0x00FF;
	}
	
	public int getID() {
		return ipHeader.get(1) >>> 16;
	}
	
	public int getLength() {
		return ipHeader.get(0) & 0x0000FFFF;
	}
	
	public int getCheckSum() {
		return ipHeader.get(2) & 0x000FFFF;
	}
	
	public byte[] getData() {
		return data;
	}
	
	public int getOffset() {
		return offset;
	}
	
	public int getHeaderLength() {
		return 20;
	}

}
