package ckcs.interfaces;

//maybe include certification to prevent man in the middle?
//have the keyServer send they're certificate to prove themselves,
//signed by a trusty CA -- keyServer's ID is signed, 
//member can decrypt with CA's public key, if the received keyServer ID
//matches the signed ID -- TRUST
//requires every member have access to CA's public key -- EXTRA
public interface RequestCode {
    final static int REQUEST_JOIN = 1;
    //---------- REQUEST PROTOCOL ---------
    //member sends REQUEST_JOIN 
    //keyServer sends serverID + Nonce N1 
    //member sends Nonce N1 + memID + Nonce N2 + port + address
    //keyServer and member start ECDH Key Agreement
    //keyServer encrypts sends port + Nonce N2 + memID + rootCode
    //keyServer addsMember
    //keyServer encrypts sends parentCode + multiCast group address + port
    //member encrypts sends parentCode
    //keyServer encrypts sends updated GK to member
    
    final static int REQUEST_LEAVE = 2;
    //------------ REQUEST LEAVE -----------
    //member sends REQUEST_LEAVE
    //keyServer sends serverID + Nonce N1
    //member sends Nonce N1 + memID + Nonce N2
    //keyServer removes member
    //keyServer sends Nonce N2 as an ACK
    
    final static int KEY_UPDATE_JOIN = 4;
    //to multicast to all members to update ON MEMBER JOIN
    //hash update their group keys
    
    final static int KEY_UPDATE_LEAVE = 8;
    //to multicast to all members to prepare for key update on leave,
    //have them stop listening to multicast group/port and temporarily leave the group?
    //server can then individually send each member which port to listen too so to receive
    //new encrypted group key via multicast
    
    
    final static int SEND_MESSAGE = 16;
    final static int RECEIVE_MESSAGE = 32;
    final static int FORCE_REMOVE = 64;
    
}
