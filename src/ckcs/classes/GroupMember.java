package ckcs.classes;

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
import javax.xml.bind.DatatypeConverter;
import ckcs.interfaces.RequestCode;
import java.nio.ByteBuffer;

public class GroupMember {
    
    final private UUID memberID; //randomly assigned
    final private SignedObject signedKey;
    final private PrivateKey privKey;
    
    private int port; //member's unqiue port to communicate with server
    private boolean isConnected; 
    private Socket servSocket;
    private ServerData servData;
        
    public GroupMember(UUID Id, int port) {
        KeyPair keyPair = Security.generateKeyPair();
        this.memberID = Id;
        this.port = port;
        this.privKey = keyPair.getPrivate();
        this.signedKey = Security.obtainTrustedSigned(keyPair.getPublic());
        this.servData = new ServerData();
    }
    
    public GroupMember(final int port) {
        this(UUID.randomUUID(), port);              
    }
    
    public void setParentCode(String parentCode) {
        this.servData.parentCode = parentCode;
    }
    
    public void setRootCode(String rootCode) {
        this.servData.rootCode = rootCode;
    }
    
    public void setKey(SecretKey key) {
        this.servData.key = key;
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
                System.out.println("Group Controller cannot be trusted! Abort connection!");
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
                System.out.println("Connection Failed -- Back Out");
                return;
            }
                
            received = readIntoBuffer(in);
            message = new String(Security.AESDecrypt(servData.key, received), StandardCharsets.UTF_8);
            this.servData.parentCode = message;
               
            byte[] encryptedMessage = Security.AESEncrypt(servData.key, servData.parentCode.getBytes(StandardCharsets.UTF_8));
            writeOutBuffer(out, encryptedMessage);
                
            received = readIntoBuffer(in);
            servData.groupKey = new SecretKeySpec(Security.AESDecrypt(servData.key, received), "AES");
            isConnected = true;
            listenToKeyServer();
            System.out.println("Connection Successful! Added to group");
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
    }
    
    private void listenToKeyServer() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.execute(new fromServer());
    }
    
    private void handleJoinUpdate() {
        servData.groupKey = Security.updateKey(servData.groupKey);
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
    }
    
    private void readMessage(byte[] received) {
        byte[] decrypted = Security.AESDecrypt(servData.groupKey, received);
        String message = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println(message);
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
    }
    
    private byte[] readIntoBuffer(ObjectInputStream in) throws IOException {
        int length = in.readInt();
        byte[] buffer = new byte[length];
        in.readFully(buffer);
        return buffer;
    }
    
    private void writeOutBuffer(ObjectOutputStream out, byte[] buffer) throws IOException {
        int length = buffer.length;
        out.writeInt(length);
        out.write(buffer);
        out.flush();
    }
    
    @Override
    public String toString() {
        return "ID: " + memberID.toString() + "  ParentCode: " + servData.parentCode + "\n" + "GK - " 
                + DatatypeConverter.printHexBinary(servData.groupKey.getEncoded());
    }

    private class fromServer implements Runnable {
        @Override 
        public void run() {
            try (ServerSocket fromServer = new ServerSocket()) {
                fromServer.setReuseAddress(true);
                fromServer.bind(new InetSocketAddress(port));
                while (isConnected) {
                    servSocket = fromServer.accept();
                    DataInputStream in = new DataInputStream(servSocket.getInputStream());
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
                Logger.getLogger(fromServer.class.getName()).log(Level.SEVERE, null, ex);
            }
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