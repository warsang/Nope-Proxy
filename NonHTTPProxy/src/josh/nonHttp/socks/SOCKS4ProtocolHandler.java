package josh.nonHttp.socks;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import burp.IBurpExtenderCallbacks;

/**
 * Implementation of the SOCKS4 protocol handler
 */
public class SOCKS4ProtocolHandler implements SOCKSProtocolHandler {
    
    // SOCKS4 constants
    private static final byte SOCKS_VERSION = 0x04;
    private static final byte CMD_CONNECT = 0x01;
    private static final byte CMD_BIND = 0x02;
    
    // SOCKS4 reply codes
    private static final byte REQUEST_GRANTED = 0x5A;
    private static final byte REQUEST_FAILED = 0x5B;
    private static final byte REQUEST_FAILED_NO_IDENTD = 0x5C;
    private static final byte REQUEST_FAILED_IDENTD_MISMATCH = 0x5D;
    
    private IBurpExtenderCallbacks callbacks;
    
    /**
     * Creates a new SOCKS4 protocol handler
     * 
     * @param callbacks The Burp callbacks
     */
    public SOCKS4ProtocolHandler(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    @Override
    public SOCKSConnectionRequest handleHandshake(Socket clientSocket, InputStream inputStream, OutputStream outputStream) throws IOException {
        // Read the SOCKS4 request
        byte[] request = new byte[8]; // Minimum SOCKS4 request size
        int bytesRead = inputStream.read(request);
        
        if (bytesRead < 8) {
            throw new IOException("Invalid SOCKS4 request: too short");
        }
        
        // Parse the request
        byte version = request[0];
        byte command = request[1];
        int port = ((request[2] & 0xFF) << 8) | (request[3] & 0xFF);
        byte[] ipBytes = new byte[4];
        System.arraycopy(request, 4, ipBytes, 0, 4);
        
        // Check the version
        if (version != SOCKS_VERSION) {
            throw new IOException("Invalid SOCKS version: " + version);
        }
        
        // Check the command
        if (command != CMD_CONNECT && command != CMD_BIND) {
            sendFailureResponse(outputStream, null, REQUEST_FAILED);
            throw new IOException("Unsupported SOCKS4 command: " + command);
        }
        
        // Read the user ID (null-terminated string)
        StringBuilder userId = new StringBuilder();
        int b;
        while ((b = inputStream.read()) != -1 && b != 0) {
            userId.append((char) b);
        }
        
        // Check if this is a SOCKS4a request (IP address is 0.0.0.x with x != 0)
        String hostname = null;
        InetAddress address = null;
        
        if (ipBytes[0] == 0 && ipBytes[1] == 0 && ipBytes[2] == 0 && ipBytes[3] != 0) {
            // SOCKS4a request with hostname
            StringBuilder hostnameBuilder = new StringBuilder();
            while ((b = inputStream.read()) != -1 && b != 0) {
                hostnameBuilder.append((char) b);
            }
            hostname = hostnameBuilder.toString();
            
            try {
                address = InetAddress.getByName(hostname);
                callbacks.printOutput("SOCKS4a: Resolved hostname " + hostname + " to " + address.getHostAddress());
            } catch (UnknownHostException e) {
                sendFailureResponse(outputStream, null, REQUEST_FAILED);
                throw new IOException("Failed to resolve hostname: " + hostname, e);
            }
        } else {
            // Standard SOCKS4 request with IP address
            address = InetAddress.getByAddress(ipBytes);
        }
        
        // Create the connection request
        SOCKSConnectionRequest connectionRequest = new SOCKSConnectionRequest(
                SOCKS_VERSION,
                command,
                SOCKSConnectionRequest.IPV4,
                address,
                hostname,
                port,
                clientSocket.getInetAddress(),
                clientSocket.getPort()
        );
        
        callbacks.printOutput("SOCKS4 request: " + connectionRequest.toString());
        
        return connectionRequest;
    }
    
    @Override
    public void sendSuccessResponse(OutputStream outputStream, SOCKSConnectionRequest request) throws IOException {
        // SOCKS4 reply: VN CD PORT IP
        byte[] response = new byte[8];
        response[0] = 0x00; // VN: Reply version (always 0)
        response[1] = REQUEST_GRANTED; // CD: Request granted
        
        // PORT: Destination port (big-endian)
        response[2] = (byte) ((request.getDestinationPort() >> 8) & 0xFF);
        response[3] = (byte) (request.getDestinationPort() & 0xFF);
        
        // IP: Destination IP address
        byte[] ipBytes = request.getDestinationAddress().getAddress();
        System.arraycopy(ipBytes, 0, response, 4, 4);
        
        outputStream.write(response);
        outputStream.flush();
    }
    
    @Override
    public void sendFailureResponse(OutputStream outputStream, SOCKSConnectionRequest request, int errorCode) throws IOException {
        // SOCKS4 reply: VN CD PORT IP
        byte[] response = new byte[8];
        response[0] = 0x00; // VN: Reply version (always 0)
        response[1] = (byte) errorCode; // CD: Error code
        
        // PORT and IP: All zeros for failure
        if (request != null) {
            // PORT: Destination port (big-endian)
            response[2] = (byte) ((request.getDestinationPort() >> 8) & 0xFF);
            response[3] = (byte) (request.getDestinationPort() & 0xFF);
            
            // IP: Destination IP address
            byte[] ipBytes = request.getDestinationAddress().getAddress();
            System.arraycopy(ipBytes, 0, response, 4, 4);
        }
        
        outputStream.write(response);
        outputStream.flush();
    }
}