package ckcs.classes;

import static java.lang.Thread.sleep;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class MainClass {
    static ArrayList<GroupMember> members = new ArrayList<>();
    static InetAddress address;
    static GroupController keyServer;
    
    public static void main(String[] args) throws UnknownHostException, InterruptedException {        
        keyServer = new GroupController(15000);
        address = InetAddress.getLocalHost();
        System.out.println(keyServer.toString());
       
        GroupMember m1 = new GroupMember(10000);
        GroupMember m2 = new GroupMember(10002);
        m1.requestJoin(address, 15000);
        m2.requestJoin(address, 15000);
        m1.sendMessage("HELLO");
        
        /*for (int i = 0; i < 64; i++) {
            addMember(10100 + i, 15000);
        }
        
        for (int i = 0; i < 64; i++) {
            removeMember(i - i);
        }*/
    }
    
    private static void printMembers() throws InterruptedException {
        sleep(100);
        for (GroupMember mem : members) 
            System.out.println(mem.toString());
    }
    
    private static void addMember(int port, int servPort) throws InterruptedException {
        GroupMember member = new GroupMember(port);
        long start = System.nanoTime();
        member.requestJoin(address, servPort);
        members.add(member);
        long end = System.nanoTime();
        //printMembers();
        System.out.println(keyServer.toString());
        System.out.println((end - start)/1000 + " microseconds");
    }
    
    private static void removeMember(int index) throws InterruptedException {
        GroupMember member = members.get(index);
        long start = System.nanoTime();
        member.requestLeave();
        members.remove(index);
        long end = System.nanoTime();
        //printMembers();
        System.out.println(keyServer.toString());
        System.out.println((end - start)/1000 + " microseconds");
        
    }
}
