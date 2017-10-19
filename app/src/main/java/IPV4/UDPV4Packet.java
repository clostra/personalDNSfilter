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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;


public class UDPV4Packet extends IPV4Packet {
	
	private IntBuffer udpHeader;
	
	
	public UDPV4Packet(byte[] packet, int offs, int len)  {
		super(packet,offs,len);
		this.udpHeader = ByteBuffer.wrap(packet,offs+20, 8).order(ByteOrder.BIG_ENDIAN).asIntBuffer();
	}
	
	
	public void updateHeader(int sourcePort, int destPort) {
		int[] hdrPacket = new int[2];
		hdrPacket[0]=(sourcePort <<16) +destPort;
		hdrPacket[1] = (len - 20) << 16;  //len - IP Header length
		udpHeader.position(0);
		udpHeader.put(hdrPacket);	
		hdrPacket[1] = hdrPacket[1]+calculateCheckSum(true);
		udpHeader.put(1, hdrPacket[1]);		
	}
	
	public int checkCheckSum() {
		return calculateCheckSum(false);		
	}
	
	private int calculateCheckSum(boolean internal) {
		int saved = ipHeader.get(2); //preserve IP Header
		ipHeader.put(2, (17<<16) + len - 20); 		// IP Pseudo Header (replace checksum by protocol (17 udp) and udp packet length for udp checksum calculation)
		int checkSum = CheckSum.chkSum(data, offset+8, len-8);		
		ipHeader.put(2, saved);  //restore the ip header
		
		if (internal && checkSum==0) 
			checkSum = 0xffff;
		
		return checkSum;
	}	
	
	public int getSourcePort() {
		return udpHeader.get(0) >>> 16;		
	}
	
	public int getDestPort() {
		return udpHeader.get(0) & 0x0000FFFF;		
	}
	
	public int getLength() {
		return udpHeader.get(1) >>> 16;		
	}
	
	public int getIPPacketLength() {
		return super.getLength();		
	}
	
	public int getCheckSum() {
		return udpHeader.get(1) & 0x0000FFFF;		
	}
	
	public int getHeaderLength() {
		return super.getHeaderLength()+8;
	}
	
	public int getOffset() {
		return super.getOffset()+super.getHeaderLength();
	}
	
	public int getIPPacketOffset() {
		return super.getOffset();
	}

}
