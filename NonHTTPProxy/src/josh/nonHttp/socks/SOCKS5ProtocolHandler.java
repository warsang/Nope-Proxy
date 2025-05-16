package josh.nonHttp.socks;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import burp.IBurpExtenderCallbacks;

/**
 * Implementation of the SOCKS5 protocol handler
 */
public class SOCKS5ProtocolHandler implements SOCKSProtocolHandler {
    
    // SOCKS5 constants
    private static final byte SOCKS_VERSION = 0x05;
    
    // SOCKS5 authentication methods
    private static final byte NO_AUTH = 0x00;
    private static final byte GSSAPI = 0x01;
    private static final byte USERNAME_PASSWORD = 0x02;
    private static final byte NO_ACCEPTABLE_METHODS = (byte) 0xFF;
    
    // SOCKS5 commands
    private static final byte CMD_CONNECT = 0x01;
    private static final byte CMD_BIND = 0x02;
    private static final byte CMD_UDP_ASSOCIATE = 0x03;
    
    // SOCKS5 address types
    private static final byte ATYP_IPV4 = 0x01;
    private static final byte ATYP_DOMAIN = 0x03;
    private static final byte ATYP_IPV6 = 0x04;
    
    // SOCKS5 reply codes
    private static final byte REP_SUCCESS = 0x00;
    private static final byte REP_GENERAL_FAILURE = 0x01;
    private static final byte REP_CONNECTION_NOT_ALLOWED = 0x02;
    private static final byte REP_NETWORK_UNREACHABLE = 0x03;
    private static final byte REP_HOST_UNREACHABLE = 0x04;
    private static final byte REP_CONNECTION_REFUSED = 0x05;
    private static final byte REP_TTL_EXPIRED = 0x06;
    private static final byte REP_COMMAND_NOT_SUPPORTED = 0x07;
    private static final byte REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
    
    private IBurpExtenderCallbacks callbacks;
    private boolean requireAuth = false;
    private String username = "";
    private String password = "";
    
    /**
     * Creates a new SOCKS5 protocol handler
     * 
     * @param callbacks The Burp callbacks
     */
    public SOCKS5ProtocolHandler(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    /**
     * Creates a new SOCKS5 protocol handler with authentication
     * 
     * @param callbacks The Burp callbacks
     * @param username The username for authentication
     * @param password The password for authentication
     */
    public SOCKS5ProtocolHandler(IBurpExtenderCallbacks callbacks, String username, String password) {
        this.callbacks = callbacks;
        this.requireAuth = true;
        this.username = username;
        this.password = password;
    }
    
    @Override
    public SOCKSConnectionRequest handleHandshake(Socket clientSocket, InputStream inputStream, OutputStream outputStream) throws IOException {
        // Step 1: Authentication method negotiation
        byte[] authRequest = new byte[2];
        int bytesRead = inputStream.read(authRequest);
        
        if (bytesRead < 2) {
            throw new IOException("Invalid SOCKS5 authentication request: too short");
        }
        
        byte version = authRequest[0];
        byte numMethods = authRequest[1];
        
        if (version != SOCKS_VERSION) {
            throw new IOException("Invalid SOCKS version: " + version);
        }
        
        byte[] methods = new byte[numMethods];
        bytesRead = inputStream.read(methods);
        
        if (bytesRead < numMethods) {
            throw new IOException("Invalid SOCKS5 authentication request: too short");
        }
        
        // Select authentication method
        byte selectedMethod = NO_ACCEPTABLE_METHODS;
        
        if (requireAuth) {
            // If authentication is required, look for USERNAME_PASSWORD method
            for (byte method : methods) {
                if (method == USERNAME_PASSWORD) {
                    selectedMethod = USERNAME_PASSWORD;
                    break;
                }
            }
        } else {
            // If no authentication is required, prefer NO_AUTH
            for (byte method : methods) {
                if (method == NO_AUTH) {
                    selectedMethod = NO_AUTH;
                    break;
                }
            }
        }
        
        // Send authentication method selection
        byte[] authResponse = new byte[2];
        authResponse[0] = SOCKS_VERSION;
        authResponse[1] = selectedMethod;
        outputStream.write(authResponse);
        outputStream.flush();
        
        if (selectedMethod == NO_ACCEPTABLE_METHODS) {
            throw new IOException("No acceptable authentication methods");
        }
        
        // Step 2: Authentication (if required)
        if (selectedMethod == USERNAME_PASSWORD) {
            // Handle username/password authentication
            byte[] authHeader = new byte[2];
            bytesRead = inputStream.read(authHeader);
            
            if (bytesRead < 2) {
                throw new IOException("Invalid SOCKS5 username/password authentication: too short");
            }
            
            byte authVersion = authHeader[0];
            byte usernameLength = authHeader[1];
            
            if (authVersion != 0x01) {
                throw new IOException("Invalid SOCKS5 username/password authentication version: " + authVersion);
            }
            
            // Read username
            byte[] usernameBytes = new byte[usernameLength];
            bytesRead = inputStream.read(usernameBytes);
            
            if (bytesRead < usernameLength) {
                throw new IOException("Invalid SOCKS5 username/password authentication: too short");
            }
            
            String clientUsername = new String(usernameBytes);
            
            // Read password
            byte passwordLength = (byte) inputStream.read();
            byte[] passwordBytes = new byte[passwordLength];
            bytesRead = inputStream.read(passwordBytes);
            
            if (bytesRead < passwordLength) {
                throw new IOException("Invalid SOCKS5 username/password authentication: too short");
            }
            
            String clientPassword = new String(passwordBytes);
            
            // Verify credentials
            boolean authSuccess = clientUsername.equals(username) && clientPassword.equals(password);
            
            // Send authentication response
            byte[] authVerifyResponse = new byte[2];
            authVerifyResponse[0] = 0x01; // Version of the auth response
            authVerifyResponse[1] = authSuccess ? (byte) 0x00 : (byte) 0x01; // 0 = success, 1 = failure
            outputStream.write(authVerifyResponse);
            outputStream.flush();
            
            if (!authSuccess) {
                throw new IOException("Authentication failed");
            }
        }
        
        // Step 3: Connection request
        byte[] requestHeader = new byte[4];
        bytesRead = inputStream.read(requestHeader);
        
        if (bytesRead < 4) {
            throw new IOException("Invalid SOCKS5 request: too short");
        }
        
        byte requestVersion = requestHeader[0];
        byte command = requestHeader[1];
        byte reserved = requestHeader[2]; // Should be 0x00
        byte addressType = requestHeader[3];
        
        if (requestVersion != SOCKS_VERSION) {
            throw new IOException("Invalid SOCKS version in request: " + requestVersion);
        }
        
        // Check command
        if (command != CMD_CONNECT && command != CMD_BIND && command != CMD_UDP_ASSOCIATE) {
            sendFailureResponse(outputStream, null, REP_COMMAND_NOT_SUPPORTED);
            throw new IOException("Unsupported SOCKS5 command: " + command);
        }
        
        // Parse destination address based on address type
        InetAddress destinationAddress = null;
        String destinationHostname = null;
        byte[] addressBytes = null;
        
        switch (addressType) {
            case ATYP_IPV4:
                addressBytes = new byte[4];
                bytesRead = inputStream.read(addressBytes);
                
                if (bytesRead < 4) {
                    throw new IOException("Invalid SOCKS5 request: too short");
                }
                
                destinationAddress = InetAddress.getByAddress(addressBytes);
                break;
                
            case ATYP_DOMAIN:
                int domainLength = inputStream.read();
                byte[] domainBytes = new byte[domainLength];
                bytesRead = inputStream.read(domainBytes);
                
                if (bytesRead < domainLength) {
                    throw new IOException("Invalid SOCKS5 request: too short");
                }
                
                destinationHostname = new String(domainBytes);
                
                try {
                    destinationAddress = InetAddress.getByName(destinationHostname);
                    callbacks.printOutput("SOCKS5: Resolved hostname " + destinationHostname + " to " + destinationAddress.getHostAddress());
                } catch (UnknownHostException e) {
                    sendFailureResponse(outputStream, null, REP_HOST_UNREACHABLE);
                    throw new IOException("Failed to resolve hostname: " + destinationHostname, e);
                }
                break;
                
            case ATYP_IPV6:
                addressBytes = new byte[16];
                bytesRead = inputStream.read(addressBytes);
                
                if (bytesRead < 16) {
                    throw new IOException("Invalid SOCKS5 request: too short");
                }
                
                destinationAddress = InetAddress.getByAddress(addressBytes);
                break;
                
            default:
                sendFailureResponse(outputStream, null, REP_ADDRESS_TYPE_NOT_SUPPORTED);
                throw new IOException("Unsupported address type: " + addressType);
        }
        
        // Read destination port
        byte[] portBytes = new byte[2];
        bytesRead = inputStream.read(portBytes);
        
        if (bytesRead < 2) {
            throw new IOException("Invalid SOCKS5 request: too short");
        }
        
        int destinationPort = ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);
        
        // Create the connection request
        SOCKSConnectionRequest connectionRequest = new SOCKSConnectionRequest(
                SOCKS_VERSION,
                command,
                addressType,
                destinationAddress,
                destinationHostname,
                destinationPort,
                clientSocket.getInetAddress(),
                clientSocket.getPort()
        );
        
        callbacks.printOutput("SOCKS5 request: " + connectionRequest.toString());
        
        return connectionRequest;
    }
    
    @Override
    public void sendSuccessResponse(OutputStream outputStream, SOCKSConnectionRequest request) throws IOException {
        // SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT
        byte[] response = null;
        byte addressType = request.getAddressType();
        
        switch (addressType) {
            case ATYP_IPV4:
                response = new byte[10]; // 4 bytes header + 4 bytes IPv4 + 2 bytes port
                break;
                
            case ATYP_DOMAIN:
                String hostname = request.getDestinationHostname();
                response = new byte[7 + hostname.length()]; // 4 bytes header + 1 byte length + hostname + 2 bytes port
                break;
                
            case ATYP_IPV6:
                response = new byte[22]; // 4 bytes header + 16 bytes IPv6 + 2 bytes port
                break;
                
            default:
                throw new IOException("Unsupported address type: " + addressType);
        }
        
        // Fill in the header
        response[0] = SOCKS_VERSION;
        response[1] = REP_SUCCESS;
        response[2] = 0x00; // Reserved
        response[3] = addressType;
        
        // Fill in the bound address and port
        if (addressType == ATYP_IPV4) {
            // IPv4 address
            byte[] ipBytes = request.getDestinationAddress().getAddress();
            System.arraycopy(ipBytes, 0, response, 4, 4);
            
            // Port (big-endian)
            response[8] = (byte) ((request.getDestinationPort() >> 8) & 0xFF);
            response[9] = (byte) (request.getDestinationPort() & 0xFF);
        } else if (addressType == ATYP_DOMAIN) {
            // Domain name
            String hostname = request.getDestinationHostname();
            response[4] = (byte) hostname.length();
            System.arraycopy(hostname.getBytes(), 0, response, 5, hostname.length());
            
            // Port (big-endian)
            response[5 + hostname.length()] = (byte) ((request.getDestinationPort() >> 8) & 0xFF);
            response[6 + hostname.length()] = (byte) (request.getDestinationPort() & 0xFF);
        } else if (addressType == ATYP_IPV6) {
            // IPv6 address
            byte[] ipBytes = request.getDestinationAddress().getAddress();
            System.arraycopy(ipBytes, 0, response, 4, 16);
            
            // Port (big-endian)
            response[20] = (byte) ((request.getDestinationPort() >> 8) & 0xFF);
            response[21] = (byte) (request.getDestinationPort() & 0xFF);
        }
        
        outputStream.write(response);
        outputStream.flush();
    }
    
    @Override
    public void sendFailureResponse(OutputStream outputStream, SOCKSConnectionRequest request, int errorCode) throws IOException {
        // SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT
        byte[] response = new byte[10]; // Minimum size for IPv4
        
        // Fill in the header
        response[0] = SOCKS_VERSION;
        response[1] = (byte) errorCode;
        response[2] = 0x00; // Reserved
        response[3] = ATYP_IPV4; // Use IPv4 for failure responses
        
        // Fill in zeros for the bound address and port
        // Address: 0.0.0.0
        response[4] = 0;
        response[5] = 0;
        response[6] = 0;
        response[7] = 0;
        
        // Port: 0
        response[8] = 0;
        response[9] = 0;
        
        outputStream.write(response);
        outputStream.flush();
    }
}