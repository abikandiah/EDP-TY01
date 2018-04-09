package ckcs.classes;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import ckcs.interfaces.RequestCode;

//should manage a multicast group, tell every member who join the 'ip-address of multicast'
public class GroupController {
    
    //GK is stored as root of tree, gets GK by calling tree.getRootKey();
    //updates GK by calling tree.setRootKey(SecretKey key);
    final private LogicalTree tree;
    final private Map<UUID, Member> groupMembers;
    final private UUID serverID;
    final private ExecutorService executor;
    final SignedObject signedKey;
    final PrivateKey privKey;
        
    public GroupController(int port) {
        KeyPair keyPair = Security.generateKeyPair();
        this.privKey = keyPair.getPrivate();
        this.signedKey = Security.obtainTrustedSigned(keyPair.getPublic());
        this.tree = new LogicalTree(3);
        this.groupMembers = new HashMap<>();
        this.executor = new ThreadPoolExecutor(5, 5, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>());
        this.serverID = UUID.randomUUID();
        tree.setGroupKey(Security.generateRandomKey());
        startListening(port);
    }
    
    //To give ability to FORCE remove members -- Tells the member that they have been removed
    //Then proceeds with the regular remove procedure
    //UUID is difficult to maintain and input --- NEED A SHORTER ID/KEY
    public void forceRemove(UUID memId) {
        Member mem = groupMembers.get(memId);
        try (Socket socket = new Socket(mem.address, mem.port);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            out.writeInt(RequestCode.FORCE_REMOVE);
            removeMember(memId);
        } catch (IOException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //start a serverSocket listening for connections -- this is BLOCKING, 
    //every accepted connection spawns a new thread to handle the accepted 
    //connections --- either JOIN/LEAVE/MESSAGE request
    private void startListening(final int port) {    
        ExecutorService ex = new ThreadPoolExecutor(2, 4, 60, TimeUnit.SECONDS, new ArrayBlockingQueue<Runnable>(6));
        ex.execute(new Server(ex, port));
    }
    
    //multicast to group members that key must be updated via hash for JOIN
    private synchronized void addMember(UUID memberID, int port, InetAddress address, SecretKey key) {
        try {
            tree.add(memberID, key);
            List<MultiUnicast> tasks = new ArrayList<>();
            for (Member mem : groupMembers.values()) {
                tasks.add(new MultiUnicast(mem, RequestCode.KEY_UPDATE_JOIN));
            }
            executor.invokeAll(tasks);
            updateKeyOnJoin();
            groupMembers.put(memberID, new Member(port, address));
        } catch (InterruptedException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private synchronized void removeMember(UUID memberID) {
        try {
            tree.remove(memberID); //removes member... Updates TREE middleKeys to most recent value with current GK
            groupMembers.remove(memberID); 
            List<MultiUnicast> tasks = new ArrayList<>();
            updateKeyOnLeave(); //generates a new random GK
            for (UUID Id : groupMembers.keySet()) {
                Member member = groupMembers.get(Id);
                byte[] encryptedGK = tree.encryptGKForMember(Id);
                tasks.add(new MultiUnicast(encryptedGK, member, RequestCode.KEY_UPDATE_LEAVE));
            }
            executor.invokeAll(tasks);
        } catch (Exceptions.NoMemberException | InterruptedException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
            
    private void handleJoin(final ObjectInputStream in, final ObjectOutputStream out) {
        try {
            //START OF MEMBER AUTHENTICATICATION PHASE
            out.writeObject(signedKey);
            SignedObject signed = (SignedObject)in.readObject();
            boolean isVerified = Security.verifyTrustedSigned(signed);
            if (!isVerified) {
                System.out.println("Member cannot be trusted! Refuse connection!");
                in.close(); out.close();
                return;
            }
            PublicKey otherPub = (PublicKey)signed.getObject();
            //END OF AUTHENTICATION PHASE
            //START OF JOIN/KEY EXCHANGE PHASE            
            int N1 = (int)(100 * Math.random() * Math.random());
            String message = serverID.toString() + "::" + N1;
            out.writeUTF(message);
            out.flush();
            message = in.readUTF();
            String parts[] = message.split("::");
            int N1Received = Integer.parseInt(parts[0]);
            if (N1 != N1Received) {
                System.out.println("Connection Failed -- Back Out");
                return;
            }
            UUID memID = UUID.fromString(parts[1]);
            int N2Received = Integer.parseInt(parts[2]);
            int memberPort = Integer.parseInt(parts[3]);
            InetAddress memberAddress = InetAddress.getByName(parts[4]);
            SecretKey sharedKey = Security.ECDHKeyAgreement(in, out, otherPub, privKey);
            
            message = "" + memberPort + "::" + N2Received + "::" + memID.toString() + "::" + tree.getRootCode();
            byte[] encryptedMessage = Security.AESEncrypt(sharedKey, message.getBytes(StandardCharsets.UTF_8));
            writeOutBuffer(out, encryptedMessage);
            
            addMember(memID, memberPort, memberAddress, sharedKey);
            String parentCode = tree.getParentCode(memID);
            message = parentCode;
            encryptedMessage = Security.AESEncrypt(sharedKey, message.getBytes(StandardCharsets.UTF_8));
            writeOutBuffer(out, encryptedMessage);
            
            byte[] received = readIntoByte(in);
            message = new String(Security.AESDecrypt(sharedKey, received), StandardCharsets.UTF_8);
            if (!parentCode.equals(message)) {
                System.out.println("Connection Failed -- Back Out");
                return;
            }
            
            encryptedMessage = Security.AESEncrypt(sharedKey, tree.getGroupKey().getEncoded());
            writeOutBuffer(out, encryptedMessage);
            System.out.println("Connection Successful! Member added");
            //END OF JOIN/KEY EXCHANGE PHASE
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
        
    private void handleLeave(final ObjectInputStream in, final ObjectOutputStream out) {
        try {
            int N1 = (int)(100 * Math.random() * Math.random());
            String message = "" + serverID.toString() + "::" + N1;
            out.writeUTF(message);
            out.flush();
            message = in.readUTF();
            String parts[] = message.split("::");
            int N1Received = Integer.parseInt(parts[0]);
            if (N1 != N1Received) {
                System.out.println("Connection Failed -- Back Out");
                return;
            }
            UUID memID = UUID.fromString(parts[1]);
            int N2Received = Integer.parseInt(parts[2]);
            removeMember(memID);
            out.writeInt(N2Received);
            out.flush();
        } catch (IOException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void sendMessage(byte[] message) {
        try {
            byte[] encryptedMessage = Security.AESEncrypt(tree.getGroupKey(), message);
            List<MultiUnicast> tasks = new ArrayList<>();
            for (Member member : groupMembers.values()) {
                tasks.add(new MultiUnicast(encryptedMessage, member, RequestCode.RECEIVE_MESSAGE));
            }
            executor.invokeAll(tasks);
        } catch (InterruptedException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private byte[]readIntoByte(ObjectInputStream in) throws IOException {
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
    
    //randomly generate new GK
    private void updateKeyOnLeave() {
        tree.setGroupKey(Security.generateRandomKey());
    }
    
    //new GK is hash of old GK
    private void updateKeyOnJoin() {
        tree.setGroupKey(Security.updateKey(tree.getGroupKey()));
    } 
    
    @Override
    public String toString() {
        return "GK - " + DatatypeConverter.printHexBinary(tree.getGroupKey().getEncoded()) + 
                "\nRootCode: " + tree.getRootCode() + "  " + tree.toString();
    }
    
    private class MultiUnicast implements Callable<Void> {
        Member member;
        int requestCode;
        byte[] message;
        
        private MultiUnicast(byte[] message, Member member, int code) {
            this(member, code);
            this.message = message;
        }
        
        private MultiUnicast(Member member, int code) {
            this.member = member;
            this.requestCode = code;
        }
        
        @Override
        public Void call() {
            try (Socket socket = new Socket(member.address, member.port)) {
                DataOutputStream out = new DataOutputStream(socket.getOutputStream()); 
                out.writeInt(requestCode);
                switch (requestCode) {
                    case RequestCode.RECEIVE_MESSAGE:
                    case RequestCode.KEY_UPDATE_LEAVE:
                        out.writeInt(message.length);
                        out.write(message);
                        break;
                    default:
                        break;
                    }
                out.flush();
                } catch (IOException ex) {
                Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
            }
            return null;
        }
    }
    
    private class Server implements Runnable {
        final private ExecutorService executor;
        final int port;
        
        private Server(ExecutorService ex, int port) {
            this.executor = ex;
            this.port = port;
        }
        
        @Override
        public void run() {
            try {
                ServerSocket server = new ServerSocket();
                server.bind(new InetSocketAddress(port));
                while (true) {
                    Socket socket = server.accept();
                    executor.execute(new RequestHandler(socket));
                }
            } catch (IOException ex) {
                Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    private class RequestHandler implements Runnable {
        final Socket socket;
        
        private RequestHandler(Socket clientSocket) {
            this.socket = clientSocket;
        }
        
        @Override
        public void run() {
            try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
                int request = in.readInt();
                switch (request) {
                    case RequestCode.REQUEST_JOIN:
                        handleJoin(in, out);
                        break;
                    case RequestCode.REQUEST_LEAVE:
                        handleLeave(in, out);
                        break;
                    case RequestCode.SEND_MESSAGE:
                        UUID memberId = UUID.fromString(in.readUTF());
                        SecretKey key = tree.getMemberKey(memberId);
                        if (key != null) {
                            int length = in.readInt();
                            byte[] received = new byte[length];
                            in.readFully(received);
                            received = Security.AESDecrypt(key, received);
                            sendMessage(received);     
                        }
                        break;
                    default:
                        break;
                }
            } catch (IOException ex) {
                Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    private class Member {
        private final InetAddress address;
        private final int port;
        
        private Member(int port, InetAddress address) {
            this.port = port;
            this.address = address;
        }
    }
}