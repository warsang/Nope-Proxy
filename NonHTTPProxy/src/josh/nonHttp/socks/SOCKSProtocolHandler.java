package josh.nonHttp.socks;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Interface for handling SOCKS protocol (both SOCKS4 and SOCKS5)
 */
public interface SOCKSProtocolHandler {
    
    /**
     * Handles the initial SOCKS handshake
     * 
     * @param clientSocket The client socket
     * @param inputStream The input stream from the client
     * @param outputStream The output stream to the client
     * @return A SOCKSConnectionRequest object containing the connection details
     * @throws IOException If an I/O error occurs
     */
    SOCKSConnectionRequest handleHandshake(Socket clientSocket, InputStream inputStream, OutputStream outputStream) throws IOException;
    
    /**
     * Sends a success response to the client
     * 
     * @param outputStream The output stream to the client
     * @param request The connection request
     * @throws IOException If an I/O error occurs
     */
    void sendSuccessResponse(OutputStream outputStream, SOCKSConnectionRequest request) throws IOException;
    
    /**
     * Sends a failure response to the client
     * 
     * @param outputStream The output stream to the client
     * @param request The connection request
     * @param errorCode The error code
     * @throws IOException If an I/O error occurs
     */
    void sendFailureResponse(OutputStream outputStream, SOCKSConnectionRequest request, int errorCode) throws IOException;
}