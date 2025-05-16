package josh.nonHttp;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import burp.IBurpExtenderCallbacks;
import josh.nonHttp.events.ProxyEvent;
import josh.nonHttp.events.ProxyEventListener;
import josh.nonHttp.socks.SOCKS4ProtocolHandler;
import josh.nonHttp.socks.SOCKS5ProtocolHandler;
import josh.nonHttp.socks.SOCKSConnectionRequest;
import josh.nonHttp.socks.SOCKSProtocolHandler;
import josh.ui.utils.InterceptData;
import josh.utils.events.PythonOutputEvent;
import josh.utils.events.PythonOutputEventListener;
import josh.utils.events.SendClosedEvent;
import josh.utils.events.SendClosedEventListener;

/**
 * SOCKS proxy server implementation that supports both SOCKS4 and SOCKS5 protocols
 */
public class SOCKSMiTMServer implements Runnable, ProxyEventListener, PythonOutputEventListener, SendClosedEventListener {
    
    public int ListenPort;
    private boolean killme = false;
    protected boolean isInterceptOn = false;
    private int interceptType = 0; // 0=both, 1=c2s, 2=s2c
    public InterceptData interceptc2s;
    public InterceptData intercepts2c;
    ServerSocket serverSocket;
    Socket connectionSocket;
    Vector<Thread> threads = new Vector<Thread>();
    Vector<SendData> sends = new Vector<SendData>();
    HashMap<SendData, SendData> pairs = new HashMap<SendData, SendData>();
    boolean isRunning = false;
    public final int INTERCEPT_C2S = 1;
    public final int INTERCEPT_S2C = 2;
    public final int INTERCEPT_BOTH = 0;
    private int IntercetpDirection = 0;
    private IBurpExtenderCallbacks Callbacks;
    private boolean MangleWithPython = false;
    private boolean requireAuth = false;
    private String username = "";
    private String password = "";
    
    /**
     * Creates a new SOCKS proxy server
     * 
     * @param callbacks The Burp callbacks
     */
    public SOCKSMiTMServer(IBurpExtenderCallbacks callbacks) {
        this.interceptc2s = new InterceptData(null);
        this.intercepts2c = new InterceptData(null);
        this.Callbacks = callbacks;
    }
    
    /**
     * Creates a new SOCKS proxy server with authentication
     * 
     * @param callbacks The Burp callbacks
     * @param username The username for authentication
     * @param password The password for authentication
     */
    public SOCKSMiTMServer(IBurpExtenderCallbacks callbacks, String username, String password) {
        this.interceptc2s = new InterceptData(null);
        this.intercepts2c = new InterceptData(null);
        this.Callbacks = callbacks;
        this.requireAuth = true;
        this.username = username;
        this.password = password;
    }
    
    /**
     * Checks if a port is available
     * 
     * @param port The port to check
     * @return True if the port is available, false otherwise
     */
    public static boolean available(int port) {
        if (port < 1 || port > 65535) {
            return false;
        }
        
        ServerSocket ss = null;
        try {
            ss = new ServerSocket(port);
            ss.setReuseAddress(true);
            return true;
        } catch (IOException e) {
        } finally {
            if (ss != null) {
                try {
                    ss.close();
                } catch (IOException e) {
                }
            }
        }
        System.out.println("SOCKS Port in use");
        return false;
    }
    
    private List _listeners = new ArrayList();
    private List _pylisteners = new ArrayList();
    
    public synchronized void addEventListener(ProxyEventListener listener) {
        _listeners.add(listener);
    }
    
    public synchronized void removeEventListener(ProxyEventListener listener) {
        _listeners.remove(listener);
    }
    
    public synchronized void addPyEventListener(PythonOutputEventListener listener) {
        _pylisteners.add(listener);
    }
    
    public synchronized void removePyEventListener(PythonOutputEventListener listener) {
        _pylisteners.remove(listener);
    }
    
    private synchronized void NewDataEvent(ProxyEvent e) {
        ProxyEvent event = e;
        Iterator i = _listeners.iterator();
        while (i.hasNext()) {
            ((ProxyEventListener) i.next()).DataReceived(event);
        }
    }
    
    public synchronized void SendPyOutput(PythonOutputEvent event) {
        Iterator i = _pylisteners.iterator();
        while (i.hasNext()) {
            ((PythonOutputEventListener) i.next()).PythonMessages(event);
        }
    }
    
    private synchronized void InterceptedEvent(ProxyEvent e, boolean isC2S) {
        ProxyEvent event = e;
        event.setMtm(this);
        Iterator i = _listeners.iterator();
        while (i.hasNext()) {
            ((ProxyEventListener) i.next()).Intercepted(event, isC2S);
        }
    }
    
    public boolean isPythonOn() {
        return this.MangleWithPython;
    }
    
    public void setPythonMangle(boolean mangle) {
        this.MangleWithPython = mangle;
    }
    
    public void KillThreads() {
        // Kill all data transfer threads
        for (int i = 0; i < threads.size(); i++) {
            try {
                if (sends.get(i).isSSL()) {
                    ((SSLSocket) sends.get(i).sock).close();
                } else {
                    ((Socket) sends.get(i).sock).close();
                }
            } catch (SocketException e) {
                // Ignore
            } catch (IOException e) {
                // Ignore
            }
            sends.get(i).killme = true;
            threads.get(i).interrupt();
        }
        
        // Close the server socket
        try {
            if (connectionSocket != null)
                connectionSocket.close();
            if (serverSocket != null)
                serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @Override
    public void run() {
        Callbacks.printOutput("Starting SOCKS Server on port " + this.ListenPort);
        this.isRunning = true;
        
        try {
            serverSocket = new ServerSocket(this.ListenPort);
            
            while (true && !killme) {
                try {
                    Callbacks.printOutput("Waiting for SOCKS connection");
                    connectionSocket = serverSocket.accept();
                    
                    connectionSocket.setReceiveBufferSize(2056);
                    connectionSocket.setSendBufferSize(2056);
                    connectionSocket.setKeepAlive(true);
                    
                    InputStream inFromClient = connectionSocket.getInputStream();
                    DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
                    
                    // Determine SOCKS version by peeking at the first byte
                    inFromClient.mark(1);
                    int version = inFromClient.read();
                    inFromClient.reset();
                    
                    // Create the appropriate protocol handler
                    SOCKSProtocolHandler protocolHandler;
                    if (version == 4) {
                        protocolHandler = new SOCKS4ProtocolHandler(Callbacks);
                    } else if (version == 5) {
                        if (requireAuth) {
                            protocolHandler = new SOCKS5ProtocolHandler(Callbacks, username, password);
                        } else {
                            protocolHandler = new SOCKS5ProtocolHandler(Callbacks);
                        }
                    } else {
                        Callbacks.printOutput("Unsupported SOCKS version: " + version);
                        connectionSocket.close();
                        continue;
                    }
                    
                    // Handle the SOCKS handshake
                    SOCKSConnectionRequest request;
                    try {
                        request = protocolHandler.handleHandshake(connectionSocket, inFromClient, outToClient);
                    } catch (IOException e) {
                        Callbacks.printOutput("SOCKS handshake failed: " + e.getMessage());
                        connectionSocket.close();
                        continue;
                    }
                    
                    // Only support CONNECT command for now
                    if (request.getCommand() != SOCKSConnectionRequest.CONNECT) {
                        Callbacks.printOutput("Unsupported SOCKS command: " + request.getCommand());
                        protocolHandler.sendFailureResponse(outToClient, request, 1); // General failure
                        connectionSocket.close();
                        continue;
                    }
                    
                    // Connect to the target server
                    Socket targetSocket;
                    try {
                        // Check if we need to use SSL/TLS
                        boolean useSSL = request.getDestinationPort() == 443;
                        
                        if (useSSL) {
                            // Create SSL socket
                            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                                    return null;
                                }
                                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                                }
                                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                                }
                            }};
                            
                            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
                            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                            
                            SSLSocketFactory ssf = sslContext.getSocketFactory();
                            targetSocket = ssf.createSocket(request.getDestinationAddress(), request.getDestinationPort());
                            ((SSLSocket) targetSocket).setReceiveBufferSize(2056);
                            ((SSLSocket) targetSocket).setSendBufferSize(2056);
                            ((SSLSocket) targetSocket).setKeepAlive(true);
                        } else {
                            // Create regular socket
                            targetSocket = new Socket(request.getDestinationAddress(), request.getDestinationPort());
                            targetSocket.setReceiveBufferSize(2056);
                            targetSocket.setSendBufferSize(2056);
                            targetSocket.setKeepAlive(true);
                        }
                        
                        // Send success response
                        protocolHandler.sendSuccessResponse(outToClient, request);
                        
                        // Set up data transfer between client and target
                        DataOutputStream outToServer = new DataOutputStream(targetSocket.getOutputStream());
                        InputStream inFromServer = targetSocket.getInputStream();
                        
                        // Create client to server data handler
                        SendData client2ServerSD = new SendData(this, true, useSSL);
                        client2ServerSD.addEventListener(this);
                        client2ServerSD.addPyEventListener(this);
                        client2ServerSD.addSendClosedEventListener(this);
                        client2ServerSD.Name = "c2s";
                        client2ServerSD.sock = connectionSocket;
                        client2ServerSD.in = inFromClient;
                        client2ServerSD.out = outToServer;
                        
                        // Create server to client data handler
                        SendData server2ClientSD = new SendData(this, false, useSSL);
                        server2ClientSD.addEventListener(this);
                        server2ClientSD.addPyEventListener(this);
                        server2ClientSD.addSendClosedEventListener(this);
                        server2ClientSD.Name = "s2c";
                        server2ClientSD.sock = targetSocket;
                        server2ClientSD.in = inFromServer;
                        server2ClientSD.out = outToClient;
                        
                        // Link the data handlers
                        client2ServerSD.doppel = server2ClientSD;
                        server2ClientSD.doppel = client2ServerSD;
                        sends.add(client2ServerSD);
                        sends.add(server2ClientSD);
                        
                        synchronized (this) {
                            pairs.put(client2ServerSD, server2ClientSD);
                        }
                        
                        // Start the data transfer threads
                        Thread c2s = new Thread(client2ServerSD);
                        Thread s2c = new Thread(server2ClientSD);
                        c2s.setName("SD-" + Calendar.getInstance().getTimeInMillis());
                        s2c.setName("SD-" + Calendar.getInstance().getTimeInMillis());
                        c2s.start();
                        s2c.start();
                        threads.add(c2s);
                        threads.add(s2c);
                        
                    } catch (ConnectException e) {
                        String message = e.getMessage();
                        Callbacks.printOutput("Connection failed: " + message);
                        protocolHandler.sendFailureResponse(outToClient, request, 5); // Connection refused
                        connectionSocket.close();
                    } catch (SSLHandshakeException e) {
                        Callbacks.printOutput("SSL handshake failed: " + e.getMessage());
                        protocolHandler.sendFailureResponse(outToClient, request, 1); // General failure
                        connectionSocket.close();
                    } catch (Exception e) {
                        Callbacks.printOutput("Connection failed: " + e.getMessage());
                        protocolHandler.sendFailureResponse(outToClient, request, 1); // General failure
                        connectionSocket.close();
                    }
                    
                } catch (Exception e) {
                    Callbacks.printOutput("SOCKS server error: " + e.getMessage());
                    e.printStackTrace();
                }
            }
            
            serverSocket.close();
            
        } catch (Exception ex) {
            Callbacks.printOutput("SOCKS server error: " + ex.getMessage());
            ex.printStackTrace();
        }
        
        Callbacks.printOutput("SOCKS server stopped");
        isRunning = false;
    }
    
    public boolean isRunning() {
        return this.isRunning;
    }
    
    public void setIntercept(boolean set) {
        this.isInterceptOn = set;
    }
    
    public boolean isInterceptOn() {
        return this.isInterceptOn;
    }
    
    public void setInterceptDir(int direction) {
        this.IntercetpDirection = direction;
    }
    
    public int getIntercetpDir() {
        return this.IntercetpDirection;
    }
    
    public void forwardC2SRequest(byte[] bytes) {
        interceptc2s.setData(bytes);
    }
    
    public void forwardS2CRequest(byte[] bytes) {
        intercepts2c.setData(bytes);
    }
    
    @Override
    public void DataReceived(ProxyEvent e) {
        NewDataEvent(e);
    }
    
    @Override
    public void Intercepted(ProxyEvent e, boolean isC2S) {
        InterceptedEvent(e, isC2S);
    }
    
    @Override
    public void PythonMessages(PythonOutputEvent e) {
        SendPyOutput(e);
    }
    
    @Override
    public void Closed(SendClosedEvent e) {
        synchronized (this) {
            SendData tmp = (SendData) e.getSource();
            
            if (pairs.containsKey(tmp)) {
                pairs.remove(tmp);
            }
        }
    }
}