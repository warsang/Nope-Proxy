package josh.nonHttp.socks;

import java.net.InetAddress;

/**
 * Represents a SOCKS connection request
 */
public class SOCKSConnectionRequest {
    
    // SOCKS command types
    public static final byte CONNECT = 0x01;
    public static final byte BIND = 0x02;
    public static final byte UDP_ASSOCIATE = 0x03;
    
    // SOCKS address types
    public static final byte IPV4 = 0x01;
    public static final byte DOMAIN_NAME = 0x03;
    public static final byte IPV6 = 0x04;
    
    private byte version;
    private byte command;
    private byte addressType;
    private InetAddress destinationAddress;
    private String destinationHostname;
    private int destinationPort;
    private InetAddress clientAddress;
    private int clientPort;
    
    /**
     * Creates a new SOCKS connection request
     * 
     * @param version The SOCKS version (4 or 5)
     * @param command The command (CONNECT, BIND, or UDP_ASSOCIATE)
     * @param addressType The address type (IPV4, DOMAIN_NAME, or IPV6)
     * @param destinationAddress The destination IP address
     * @param destinationHostname The destination hostname (if address type is DOMAIN_NAME)
     * @param destinationPort The destination port
     * @param clientAddress The client IP address
     * @param clientPort The client port
     */
    public SOCKSConnectionRequest(byte version, byte command, byte addressType, 
            InetAddress destinationAddress, String destinationHostname, 
            int destinationPort, InetAddress clientAddress, int clientPort) {
        this.version = version;
        this.command = command;
        this.addressType = addressType;
        this.destinationAddress = destinationAddress;
        this.destinationHostname = destinationHostname;
        this.destinationPort = destinationPort;
        this.clientAddress = clientAddress;
        this.clientPort = clientPort;
    }
    
    /**
     * Gets the SOCKS version
     * 
     * @return The SOCKS version
     */
    public byte getVersion() {
        return version;
    }
    
    /**
     * Gets the command
     * 
     * @return The command
     */
    public byte getCommand() {
        return command;
    }
    
    /**
     * Gets the address type
     * 
     * @return The address type
     */
    public byte getAddressType() {
        return addressType;
    }
    
    /**
     * Gets the destination IP address
     * 
     * @return The destination IP address
     */
    public InetAddress getDestinationAddress() {
        return destinationAddress;
    }
    
    /**
     * Gets the destination hostname
     * 
     * @return The destination hostname
     */
    public String getDestinationHostname() {
        return destinationHostname;
    }
    
    /**
     * Gets the destination port
     * 
     * @return The destination port
     */
    public int getDestinationPort() {
        return destinationPort;
    }
    
    /**
     * Gets the client IP address
     * 
     * @return The client IP address
     */
    public InetAddress getClientAddress() {
        return clientAddress;
    }
    
    /**
     * Gets the client port
     * 
     * @return The client port
     */
    public int getClientPort() {
        return clientPort;
    }
    
    /**
     * Returns a string representation of the connection request
     * 
     * @return A string representation of the connection request
     */
    @Override
    public String toString() {
        String destination = (destinationHostname != null) ? destinationHostname : destinationAddress.getHostAddress();
        return String.format("SOCKS%d %s %s:%d", version, 
                (command == CONNECT) ? "CONNECT" : 
                (command == BIND) ? "BIND" : 
                (command == UDP_ASSOCIATE) ? "UDP_ASSOCIATE" : "UNKNOWN", 
                destination, destinationPort);
    }
}