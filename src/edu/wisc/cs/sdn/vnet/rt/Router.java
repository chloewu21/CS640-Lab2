package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		// Check if frame contains IPv4 packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}
		
		// Verify checksum
		IPv4 payload = (IPv4) etherPacket.getPayload();
		short checksum = payload.getChecksum();
		payload.resetChecksum();
		payload.serialize();
		if (checksum != payload.getChecksum()) {
			return;
		}
		
		// Decrement TTL by 1
		byte ttl = payload.getTtl();
		ttl--;
		if (ttl == 0) {
			return; // drop if 0
		}
		payload.setTtl(ttl);

		// Check for IP match
		for (Iface iface : this.getInterfaces().values()) {
			if (payload.getDestinationAddress() == iface.getIpAddress()) {
				return; // drop if match
			}
		}

		// Find longest prefix match in routing table
		RouteEntry longestMatch = this.routeTable.lookup(payload.getDestinationAddress());
		if (longestMatch == null) {
			return; // drop if no match
		}

		// Find next hop MAC address
		int nextHop = longestMatch.getGatewayAddress();
		if (nextHop == 0) {
			nextHop = payload.getDestinationAddress();
		}

		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (arpEntry == null) {
			return; // drop if no ARP entry for next hop
		}	

		// Set source and destination MAC addresses
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
		etherPacket.setSourceMACAddress(longestMatch.getInterface().getMacAddress().toBytes());

		// Recompute checksum and send
		payload.resetChecksum();
		payload.serialize();
		
		sendPacket(etherPacket, longestMatch.getInterface());

		/********************************************************************/
	}
}
