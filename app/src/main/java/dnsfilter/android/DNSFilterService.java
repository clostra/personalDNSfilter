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

package dnsfilter.android;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.StringTokenizer;
import java.util.Vector;

import util.ExecutionEnvironment;
import util.ExecutionEnvironmentInterface;
import util.Logger;
import IPV4.IPV4Packet;
import IPV4.UDPV4Packet;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import dnsfilter.DNSCommunicator;
import dnsfilter.DNSFilterManager;
import dnsfilter.DNSResolver;

public class DNSFilterService extends VpnService implements Runnable, ExecutionEnvironmentInterface {

	private static String VIRTUALDNS="10.10.10.10";
	
	public static DNSFilterManager DNSFILTER = null;
	private static DNSFilterService INSTANCE=null;
			
	private ParcelFileDescriptor vpnInterface;
	FileInputStream in = null;
	FileOutputStream out =null;

	Builder builder = new Builder();	
	private static WakeLock wakeLock = null;

	
	public static void detectDNSServers() {		
		
		Logger.getLogger().logLine("Detecting DNS Servers...");
		
		DNSFilterManager dnsFilterMgr = DNSFILTER;

		if (dnsFilterMgr == null)
			return;

		boolean detect = Boolean.parseBoolean(dnsFilterMgr.getConfig().getProperty("detectDNS", "true"));		

		Vector<InetAddress> dnsAdrs = new Vector<InetAddress>();

		if (detect) {
			try {
				Class<?> SystemProperties = Class.forName("android.os.SystemProperties");
				Method method = SystemProperties.getMethod("get", new Class[] { String.class });

				for (String name : new String[] { "net.dns1", "net.dns2", "net.dns3", "net.dns4", }) {
					String value = (String) method.invoke(null, name);
					if (value != null && !value.equals("")) {
						Logger.getLogger().logLine("DNS:" + value);
						if (!value.equals(VIRTUALDNS))
							dnsAdrs.add(InetAddress.getByName(value));
					}
				}
			} catch (Exception e) {
				Logger.getLogger().logException(e);
			}
		}		
		if (dnsAdrs.isEmpty()) { //fallback
			StringTokenizer fallbackDNS = new StringTokenizer(dnsFilterMgr.getConfig().getProperty("fallbackDNS", ""),";");
			int cnt = fallbackDNS.countTokens();
			for (int i = 0; i < cnt; i++) {
				String value = fallbackDNS.nextToken().trim();
				Logger.getLogger().logLine("DNS:" + value);
				try {
					dnsAdrs.add(InetAddress.getByName(value));
				} catch (UnknownHostException e) {
					Logger.getLogger().logException(e);
				}				
			}
		}			
		DNSCommunicator.getInstance().setDNSServers(dnsAdrs.toArray(new InetAddress[dnsAdrs.size()]));
	}
	
	public void run() {
		Logger.getLogger().logLine("VPN Runner Thread started!" );
		detectDNSServers();	
		try {			
			while (true) {
				
				byte[] data = new byte[1024];
				int length = in.read(data);
				
				if (length > 0) {
					try {					
						IPV4Packet parsedIP = new IPV4Packet(data, 0, length);
						
						if (parsedIP.checkCheckSum() != 0)
							throw new IOException("IP Header Checksum Error!");					
						
						if (parsedIP.getProt() == 1) {
							Logger.getLogger().logLine("Received ICMP Paket Type:" + data[20]);
						}
						if (parsedIP.getProt() == 17) {
							
							UDPV4Packet parsedPacket = new UDPV4Packet(data, 0, length);
							if (parsedPacket.checkCheckSum() != 0)
								throw new IOException("UDP packet Checksum Error!");							
							
							DatagramSocket dnsSocket = new DatagramSocket();							

							if (!protect(dnsSocket)) {
								throw new IOException("Cannot protect the tunnel");
							}							
							new Thread(new DNSResolver(dnsSocket, parsedPacket, out)).start();
						}
					} catch (IOException e) {
						Logger.getLogger().logLine("IOEXCEPTION: "+e.toString() );
					} catch (Exception e) {
						Logger.getLogger().logException(e);
					}
				} else
					Thread.sleep(1000);
			}

		} catch (Exception e) {
			if (vpnInterface!=null) //not stopped
				Logger.getLogger().logLine("EXCEPTION: "+e.toString() );
			Logger.getLogger().logLine("VPN Runner Thread terminated!" );
		} 
	}
	

	
	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		INSTANCE = this;
		ExecutionEnvironment.setEnvironment(this);
		registerReceiver(new ConnectionChangeReceiver(), new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));
		
		if (DNSFILTER != null) {
			Logger.getLogger().logLine("DNS Filter already running!");
			
		} else {			
			try {
				DNSFilterManager.WORKDIR = DNSProxyActivity.WORKPATH.getAbsolutePath() + "/";
				DNSFILTER = new DNSFilterManager();
				DNSFILTER.init();				
			} catch (Exception e) {
				DNSFILTER = null;
				Logger.getLogger().logException(e);
				return START_STICKY;
			}
		}
		try {
			Intent notificationIntent = new Intent(this, DNSProxyActivity.class);
			PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, 0);
			builder.setSession("DNS Filter").addAddress("10.0.2.15", 24).addDnsServer(VIRTUALDNS).addRoute(VIRTUALDNS, 32);			
			
			// Android 7 has an issue with VPN in combination with some google apps - bypass the filter
			if (Build.VERSION.SDK_INT>=24 && Build.VERSION.SDK_INT <= 25) { // Android 7
				Logger.getLogger().logLine("Running on SDK"+Build.VERSION.SDK_INT);
				builder.addDisallowedApplication("com.android.vending"); //white list play store	
				builder.addDisallowedApplication("com.google.android.apps.docs"); //white list google drive
				builder.addDisallowedApplication("com.google.android.apps.photos"); //white list google photos
				builder.addDisallowedApplication("com.google.android.gm"); //white list gmail				
			}
			
			
			vpnInterface = builder.setConfigureIntent(pendingIntent).establish();
			
			if (vpnInterface != null) {
				in = new FileInputStream(vpnInterface.getFileDescriptor());
				out = new FileOutputStream(vpnInterface.getFileDescriptor());
				Logger.getLogger().logLine("VPN Connected!");
				new Thread(this).start();			
			}
			else Logger.getLogger().logLine("Error! Cannot get VPN Interface! Try restart!");			

		} catch (Exception e) {
			Logger.getLogger().logException(e);
		}

		return START_STICKY;
	}

	
	@Override
	public void onDestroy() {
		Logger.getLogger().logLine("destroyed");		
		stopVPN();		
		super.onDestroy();
	}
	
	private boolean stopVPN() {
		try {
			if (DNSFILTER != null && !DNSFILTER.canStop()) {
				Logger.getLogger().logLine("Cannot stop - pending operation!");
				return false;
			}
			
			ParcelFileDescriptor runningVPN = vpnInterface;
			if (runningVPN  != null) {
				vpnInterface=null;
				in.close();
				out.close();
				runningVPN.close();			
			}
			if (DNSFILTER != null)	{		
				DNSFILTER.stop();
				Logger.getLogger().logLine("DNSFilter stopped!");
			}		
			DNSFILTER = null;
			Thread.sleep(200);
			return true;
		} catch (Exception e) {
			Logger.getLogger().logException(e);
			return false;
		}
	}
	
	public static boolean stop() {
		if (INSTANCE == null)
			return true;
		else {
			if (INSTANCE.stopVPN()) {
				INSTANCE = null;
				return true;
			} else
				return false;
		}
	}


	public static String openConnectionsCount() {
		return ""+DNSResolver.getResolverCount();
	}


	@Override
	public void wakeLock() {
		wakeLock = ((PowerManager) getSystemService(Context.POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "My Tag");
		wakeLock.acquire();			
	}

	@Override
	public void releaseWakeLock() {
		WakeLock wl = wakeLock;
		if (wl != null)
			wl.release();		
	}


}