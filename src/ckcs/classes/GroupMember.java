package ckcs.classes;

import ckcs.interfaces.MemberUI;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignedObject;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import ckcs.interfaces.RequestCode;
import java.nio.ByteBuffer;
import javax.xml.bind.DatatypeConverter;

public class GroupMember {
    
    final private UUID memberID; //randomly assigned
    final private SignedObject signedKey;
    final private PrivateKey privKey;
    final private InterfaceData uiData;
    
    private int port; //member's unqiue port to communicate with server
    private boolean isConnected; 
    private MemberUI ui;
    private ServerSocket servSocket;
    private ServerData servData;
        
    public GroupMember(UUID Id, int port) {
        KeyPair keyPair = Security.generateKeyPair();
        this.uiData = new InterfaceData();
        this.memberID = Id;
        this.port = port;
        this.privKey = keyPair.getPrivate();
        this.signedKey = Security.obtainTrustedSigned(keyPair.getPublic());
        this.servData = new ServerData();
    }
    
    public GroupMember(final int port, MemberUI ui) {
        this(port);
        this.ui = ui;
    }
    
    public GroupMember(final int port) {
        this(UUID.randomUUID(), port);              
    }
    
    public UUID getId() {
        return memberID;
    }

    public void requestJoin(final InetAddress address, final int portNumber) {
        servData.serverAddress = address;
        servData.serverPort = portNumber;
        try (Socket socket = new Socket(address, portNumber);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {   
            out.writeInt(RequestCode.REQUEST_JOIN);
            //AUTHENTICATION PHASE
            out.writeObject(signedKey);
            SignedObject signed = (SignedObject)in.readObject();
            boolean isVerified = Security.verifyTrustedSigned(signed);
            if (!isVerified) {
                uiData.state = "Group Controller cannot be trusted! Abort connection!";
                uiData.update();
                socket.close();
                return;
            }
            PublicKey otherPub = (PublicKey)signed.getObject();   
            //END OF AUTHENTICATION PHASE
            //START OF JOIN/KEY EXCHANGE PHASE
            String message = in.readUTF();
            String parts[] = message.split("::");
            this.servData.serverID = UUID.fromString(parts[0]);
            int N1Received = Integer.parseInt(parts[1]);
                
            int N2 = (int)(1000 * Math.random() * Math.random());
            message = "" + N1Received + "::" + memberID.toString() + "::" + N2 + "::" + 
                    port + "::" + InetAddress.getLocalHost().getHostAddress();
            out.writeUTF(message);
            out.flush();
            this.servData.key = Security.ECDHKeyAgreement(in, out, otherPub, privKey);
                
            byte[] received = readIntoBuffer(in);
            message = new String(Security.AESDecrypt(servData.key, received), StandardCharsets.UTF_8);
            parts = message.split("::");
            int N2Received = Integer.parseInt(parts[1]);
            UUID memID = UUID.fromString(parts[2]);
            this.servData.rootCode = parts[3];
            if (N2Received != N2 || !memID.equals(memberID)) {
                uiData.state = "Connection Failed -- Back Out";
                uiData.update();
                return;
            }
                
            received = readIntoBuffer(in);
            message = new String(Security.AESDecrypt(servData.key, received), StandardCharsets.UTF_8);
            this.servData.parentCode = message;
            uiData.parentCode = message;
                
            received = readIntoBuffer(in);
            byte[] GK = Security.AESDecrypt(servData.key, received);
            uiData.groupKey = GK;
            servData.groupKey = new SecretKeySpec(GK, "AES");
            isConnected = true;
            listenToKeyServer();
            uiData.state = "Connection Successful! Added to group";
            uiData.update();
            //END OF JOIN/KEY EXCHANGE PHASE
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void requestLeave() {
        try (Socket socket = new Socket(servData.serverAddress, servData.serverPort); 
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {    
            out.writeInt(RequestCode.REQUEST_LEAVE);
            out.flush();
            String message = in.readUTF();
            String parts[] = message.split("::");
            UUID servID = UUID.fromString(parts[0]);
            if (!servID.equals(servData.serverID)) {
                System.out.println("Connection Failed -- Backout");
                return;
            }
            int N1Received = Integer.parseInt(parts[1]);
            int N2 = (int)(100 * Math.random() * Math.random());
            message = "" + N1Received + "::" + memberID.toString() + "::" + N2;
            out.writeUTF(message);
            out.flush();
            int N2Received = in.readInt();
            if (N2 == N2Received) {
                System.out.println("Successful Leave");
            }
            disconnect();
        } catch (IOException ex) {
            Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void sendMessage(String message) {
        byte[] msg = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = Security.AESEncrypt(servData.key, msg);
        try (Socket socket = new Socket(servData.serverAddress, servData.serverPort); 
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            int length = encrypted.length;
            out.writeInt(RequestCode.SEND_MESSAGE);
            out.writeUTF(memberID.toString());
            out.writeInt(length);
            out.write(encrypted);
        } catch (IOException ex) {
            Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
        }
        uiData.state = "Message sent to group.";
        uiData.update();
    }
    
    private void listenToKeyServer() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.execute(new fromServer());
    }
    
    private void handleJoinUpdate() {
        servData.groupKey = Security.updateKey(servData.groupKey);
        uiData.groupKey = servData.groupKey.getEncoded();
        uiData.state = "A member has joined the group. Group Key has been updated via one-way hash.";
        uiData.update();
    }
   
    //receive a byte[] containing the new encrypted GK
    //levels -- how many times it has been encrypted (encryption levels)
    private void handleLeaveUpdate(byte[] encrypted) {
        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        int strLen = buffer.getInt();
        byte[] str = new byte[strLen];
        buffer.get(str, 0, strLen);
        int level = buffer.getInt();
        int GKLen = buffer.getInt();
        byte[] encrypGK = new byte[GKLen];
        buffer.get(encrypGK, 0, GKLen);
        
        String parent = new String(str, StandardCharsets.UTF_8);
        servData.parentCode = parent;
        
        List<String> path = pathToRoot(servData.parentCode);
        if (level > path.size() || path.isEmpty()) {
            encrypted = Security.AESDecrypt(servData.key, encrypGK);
        } else {
            Iterator<String> it = path.listIterator(path.size() - level);
            String nodeCode = it.next();
            SecretKey middleKey = Security.middleKeyCalculation(servData.groupKey, nodeCode);
            encrypted = Security.AESDecrypt(middleKey, encrypGK);    
        }
        servData.groupKey = new SecretKeySpec(encrypted, "AES");
        uiData.groupKey = encrypted;
        uiData.parentCode = parent;
        uiData.state = "A member has left the group. Group Key and ParentCode have been updated via Middle Node Key.";
        uiData.update();
    }
    
    private void readMessage(byte[] received) {
        byte[] decrypted = Security.AESDecrypt(servData.groupKey, received);
        uiData.message = new String(decrypted, StandardCharsets.UTF_8);
        uiData.state = "Message received";
        uiData.update();
    }
    
    private String removeDigit(String parentCode) {
        return parentCode.substring(0, parentCode.length() - 1);
    }
    
    private List<String> pathToRoot(String parentCode) {
        List<String> path = new ArrayList<>();
        while (!parentCode.equals(this.servData.rootCode)) {
            path.add(parentCode);
            parentCode = removeDigit(parentCode);
        }
        return path;
    }
    
    private void disconnect() throws IOException {
        isConnected = false;
        servSocket.close();
        servData = null;
        uiData.groupKey = "".getBytes();
        uiData.parentCode = "";
        uiData.state = "Removed from the group. You are now disconnected.";
        uiData.update();
    }
    
    private byte[] readIntoBuffer(ObjectInputStream in) throws IOException {
        int length = in.readInt();
        byte[] buffer = new byte[length];
        in.readFully(buffer);
        return buffer;
    }
    
    @Override
    public String toString() {
        return "ID: " + memberID.toString() + "  ParentCode: " + servData.parentCode + "\n" + "GK - " 
                + DatatypeConverter.printHexBinary(servData.groupKey.getEncoded());
    }

    private class fromServer implements Runnable {
        @Override 
        public void run() {
            try {
                servSocket = new ServerSocket();
                servSocket.setReuseAddress(true);
                servSocket.bind(new InetSocketAddress(port));
                while (isConnected) {
                    Socket socket = servSocket.accept();
                    DataInputStream in = new DataInputStream(socket.getInputStream());
                    int code = in.readInt();
                    switch (code) {
                        case RequestCode.KEY_UPDATE_JOIN:
                            handleJoinUpdate();
                            break;
                        case RequestCode.KEY_UPDATE_LEAVE:
                            byte[] encrypted = new byte[in.readInt()];
                            in.readFully(encrypted);
                            handleLeaveUpdate(encrypted);
                            break;
                        case RequestCode.RECEIVE_MESSAGE:
                            byte[] received = new byte[in.readInt()];
                            in.readFully(received);
                            readMessage(received);
                            break;
                        case RequestCode.FORCE_REMOVE:
                            disconnect();
                            break;
                    }   
                }
            } catch (IOException ex) {
                if (isConnected) {
                    Logger.getLogger(fromServer.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }
    
    public class InterfaceData {
        private String message;
        private String parentCode;
        private String state;
        private byte[] groupKey;
        
        private void update() {
            if (ui != null) {
                ui.updateState(this);
            }
        }
        
        public String getMessage() {
            return message;
        }
        
        public String getParentCode() {
            return parentCode;
        }
        
        public String getState() {
            return state;
        }
        
        public byte[] getGK() {
            return groupKey;
        }
    }
    
    private class ServerData {
        private UUID serverID;
        private InetAddress serverAddress;
        private int serverPort;
        private SecretKey key; //Group Controller key exchange 
        private SecretKey groupKey;
        private String parentCode; //Should be obtained from GroupController via LogicalTree
        private String rootCode; //rootCode of logical tree
    }  
}