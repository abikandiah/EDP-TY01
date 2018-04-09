package ckcs.classes;

import ckcs.classes.Exceptions.NoMemberException;
import ckcs.interfaces.Node;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import javax.crypto.SecretKey;

//Tree DATA STRUCTURE for CKCS PROTOCOL
//tree constructed as a binary tree, strictly to hold data for KeyServer
//and some minimum data manipulation 
//enclose all key info and key handling in this class
public class LogicalTree {
    
    private TreeMap<Integer, Map<String, MiddleNode>> middleNodes; //red-black based; ordered mapping via keys (node codes)
    private TreeMap<Integer, List<String>> codeValuesTaken; //nodeCode values that have been taken (so to not repeat nodeCode values in siblings)
    private HashMap<UUID, LeafNode> leafNodes; //UUID = groupMember ID
    private MiddleNode rootNode;
    private int numberOfCodeDigits; // for rootNode; e.g. 20143 = 5
    
    //generates new logical tree for KeyServer to maintain
    //starts with root node as group key
    public LogicalTree(int numberOfCodeDigits) {
        this.middleNodes = new TreeMap<>();
        this.codeValuesTaken = new TreeMap<>();
        this.leafNodes = new HashMap<>(); 
        this.numberOfCodeDigits = numberOfCodeDigits;
        this.rootNode = new MiddleNode();
        
        putMiddle(rootNode);
    }
    
    public SecretKey getMemberKey(UUID memId) {
        LeafNode member = leafNodes.get(memId);
        return member.key;
    }
    
    public SecretKey getGroupKey() {
        return this.rootNode.key;
    }
    
    public void setGroupKey(SecretKey key) {
        this.rootNode.key = key;
    }
    
    //for group controller to give group member their parentCode
    public String getParentCode(UUID memberId) {
        LeafNode child = leafNodes.get(memberId);
        return child.parentCode;
    }
    
    public String getRootCode() {
        return rootNode.nodeCode;
    }
    
    @Override
    public String toString() {
        return "members: " + leafNodes.values().size();
    }
    
    //KeyServer requests to encrypt GK to send to a member
    //Finds pathToRoot of member, and finds highest (closest to root) middleNode in that path
    //and uses it's middleKey to encrypt the GK and send to the member
    //Starts from the middleNode directly after the rootNode and moves down towards the member leafNode parent
    //IF ALL middleNodes on pathToRoot are exposed by a LEAVE -- encrypt with MEMBER KEY
    //Keep track of LEVEL and send along with encrypted GK -- so Member knows which middleNode the key was encrypted by
    //Each middleNode in a pathToRoot has a different LEVEL -- the tree's height/level
    public byte[] encryptGKForMember(UUID memberId) throws NoMemberException {
        LeafNode member = leafNodes.get(memberId);
        if (member == null) 
            throw new NoMemberException("Given memberId does not match a registered member");
        
        int level = 0;
        ArrayList<String> path = pathToRoot(member);
        ListIterator<String> it = path.listIterator(path.size());
        while (it.hasPrevious()) {
            String nodeCode = it.previous();
            MiddleNode middle = getMiddle(nodeCode);
            level++;
            if (!middle.exposed) {
                return encryptGK(middle.key, member, level);
            }
        }
        level++;
        return encryptGK(member.key, member, level);
    }
    
    private byte[] encryptGK(SecretKey key, LeafNode member, int level) {
        byte[] GK = Security.AESEncrypt(key, rootNode.key.getEncoded());
        byte[] code = member.parentCode.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(GK.length + code.length + (3 * 4));
        buffer.putInt(code.length);
        buffer.put(code);
        buffer.putInt(level);
        buffer.putInt(GK.length);
        buffer.put(GK, 0, GK.length);
        return buffer.array();
    }
        
    //REMOVES a member's leafNode from the tree, and any MiddleNodes if necessary
    //has MULTIPLE remove cases/situations... handles them all
    //Sets the necessary middleNodes to exposed -- the middleNodes whose nodeCode is known by the LEAVING member
    //Set to exposed so that these middleNodes are NOT USED (AVOIDED) for encrypting the NEW GK for remaining members
    public synchronized void remove(UUID memberId) throws NoMemberException {
        LeafNode member = leafNodes.get(memberId);
        if (member == null) {
            throw new Exceptions.NoMemberException("Given member does not exist in tree.");
        }
        
        MiddleNode parent = getMiddle(member.parentCode);
        parent.children.remove(memberId);
        parent.numberOfChildren--;
        setExposed(pathToRoot(member));
        
        if (parent.children.isEmpty()) { //means there are no LEAFNODE CHILD -- it has MIDDLENODE CHILD
            int siblingDigitSize = parent.nodeCode.length() + 1;
            List<String> values = codeValuesTaken.get(siblingDigitSize); //get all nodeCodes of SIBLING NODE length
            if (values != null) {
                MiddleNode middleSibling = null;
                for (String nodeCode : values) {
                    MiddleNode middle = getMiddle(nodeCode);
                    if (middle.parentCode.equals(parent.nodeCode)) { //sibling has same parent code as member  
                        middleSibling = middle;   
                        break;                                  //a sibling middleNode EXISTS
                    }
                }
                if (middleSibling != null) {
                    handleMiddleSibling(parent, middleSibling);
                }
            }
        } else { //the leaving member has ONE LEAFNODE sibling, move the sibling up ONE level to parentsParent, get rid of parent middleNode
            String newParentCode = parent.parentCode;
            if (newParentCode != null) { // make sure the parent is not ROOT
                MiddleNode newParent = getMiddle(newParentCode);
                UUID siblingId = parent.children.get(0);
                LeafNode sibling = leafNodes.get(siblingId);
                removeMiddle(parent.nodeCode);
                newParent.numberOfChildren--;
                    
                newParent.children.add(siblingId);
                newParent.numberOfChildren++;
                sibling.parentCode = newParentCode;
            } 
        }
        leafNodes.remove(memberId);
        updateMiddleKeys();
    } 
    
    //FOR REMOVE -- appropriately repositions the SIBLING MIDDLE NODE's children
    private void handleMiddleSibling(MiddleNode parent, MiddleNode sibling) {
        int siblingDigitSize = sibling.nodeCode.length();
        int childDigitSize = siblingDigitSize + 1;
        List<String> codes = new ArrayList<>(codeValuesTaken.get(childDigitSize));
        List<String> children = new ArrayList<>();
        for (String nodeCode : codes) {
            MiddleNode child = getMiddle(nodeCode);
            if (child.parentCode.equals(sibling.nodeCode) && children.size() < 2) {
                children.add(nodeCode);
            }
        }
    
        removeMiddle(sibling.nodeCode);
        parent.numberOfChildren--;
        MiddleNode parentsParent = null;
        if (parent.parentCode != null) {
            System.out.println(parent.parentCode.length());
            parentsParent = getMiddle(parent.parentCode);
        }
        if (parentsParent != null && parentsParent.numberOfChildren == 1) { // move middleSibling's CHILDREN to parentsParent
            removeMiddle(parent.nodeCode);
            parentsParent.numberOfChildren--;
            for (String nodeCode : children) {
                updateNodeCodes(nodeCode, parentsParent.nodeCode);
                parentsParent.numberOfChildren++;
            }
            for (UUID Id : sibling.children) {
                LeafNode child = leafNodes.get(Id);
                child.parentCode = parentsParent.nodeCode;
                parentsParent.children.add(Id);
                parentsParent.numberOfChildren++;
            }
        } else {
            for (String nodeCode : children) {
                updateNodeCodes(nodeCode, parent.nodeCode);
                parent.numberOfChildren++;
            }   
            for (UUID Id : sibling.children) {
                LeafNode child = leafNodes.get(Id);
                child.parentCode = parent.nodeCode;
                parent.children.add(Id);
                parent.numberOfChildren++;
            }
        }
    }
    
    //firts iterates through iteratorChild -- which goes through each middleNode and adds new member only if 
    //that middleNode has space for children -- it's numberOfChildren < maxNumberOfChildren
    //if NO middleNode exists with space for children, iterate through MiddleNodes and replace a LEAFNODE with
    //a new MIDDLENODE and attach new member to that NEW MIDDLENODE
    //This ensures that ALL MIDDLENODES are full with children before deciding to replace a CHILD with a new MIDDLENODE 
    public synchronized void add(UUID memberId, SecretKey key) {
        if (rootNode.numberOfChildren == 2) {
            for (Integer size : middleNodes.keySet()) {
                Map<String, MiddleNode> middles = middleNodes.get(size);
                for (MiddleNode mid : middles.values()) {
                    if (addMiddleAndLeaf(mid, memberId, key)) {
                        return;
                    }
                }
            }
        } else {
            LeafNode child = new LeafNode(rootNode.nodeCode, key);
            rootNode.children.add(memberId);
            rootNode.numberOfChildren++;
            leafNodes.put(memberId, child);
        }
    }

    //removes a child leaf, replaces it with a new middlenode, attaches removed child leaf to 
    //the new middlenode, then attaches new group member leaf node to new middlenode 
    private boolean addMiddleAndLeaf(MiddleNode parent, UUID memberId, SecretKey key) {
        Iterator<UUID> it = parent.children.iterator();
        if (it.hasNext()) {
            UUID childId = it.next();
            LeafNode childOne = leafNodes.get(childId);
            MiddleNode middle = new MiddleNode(parent.nodeCode);
            LeafNode childTwo = new LeafNode(middle.nodeCode, key);

            parent.children.remove(childId);
            middle.children.add(childId);
            middle.children.add(memberId);
            middle.numberOfChildren = 2;
            childOne.parentCode = middle.nodeCode;
            putMiddle(middle);
            leafNodes.put(memberId, childTwo);
            return true;            
        }
        return false;       
    }
    
    //Updates the middleKey values for every MiddleNode AFTER A LEAVE -- because only then is it actually needed
    //MiddleKey values are NOT NEEDED for member Join
    //It updates them to the CURRENT GK -- BEFORE member LEAVES -- NOT THE NEW GK AFTER LEAVE
    //or else all members won't have matching middle keys -- since they only have the CURRENT GK and 
    //receive the NEW GK through these middle keys
    private void updateMiddleKeys() {
        List<Integer> sizes = new ArrayList<>(middleNodes.keySet());
        sizes.remove(Integer.valueOf(numberOfCodeDigits));
        for (Integer size : sizes) {
            Map<String, MiddleNode> nodes = middleNodes.get(size);
            for (MiddleNode mid : nodes.values()) {
                mid.key = Security.middleKeyCalculation(rootNode.key, mid.nodeCode);
            }
        }
    }
    
    //set all MiddleNods on pathToRoot of LEAVING member as exposed
    private void setExposed(ArrayList<String> exposedPath) {
        for (String code : exposedPath) {
            MiddleNode node = getMiddle(code);
            node.exposed = true;
        }
    }
    
    private ArrayList<String> pathToRoot(LeafNode leaf) {
        ArrayList<String> path = new ArrayList<>();
        String parentCode = leaf.parentCode;
        while (!parentCode.equals(rootNode.nodeCode)) {
            path.add(parentCode);
            parentCode = removeDigit(parentCode);
        }
        return path;
    }
    
    private String removeDigit(String parentCode) {
        return parentCode.substring(0, parentCode.length() - 1);
    }
    
    private String addRandomDigit(String parentCode) {
        int digitSize = parentCode.length() + 1;
        
        if (codeValuesTaken.get(digitSize) == null) {
            ArrayList<String> codes = new ArrayList<>();
            codeValuesTaken.put(digitSize, codes);
        }
        List<String> codes = codeValuesTaken.get(digitSize);
        String code = parentCode + (int)(10 * Math.random());
        while (codes.contains(code)) {
            code = parentCode + (int)(10 * Math.random());
        }
        return code;
    }
    
    //to update the nodeCodes and parentNodeCodes of all middleNodes under parameter - node
    private void updateNodeCodes(String nodeCode, String newParentCode) {
        MiddleNode middle = getMiddle(nodeCode);
        int digitSize = nodeCode.length();
        
        middle.parentCode = newParentCode;
        middle.nodeCode = addRandomDigit(newParentCode);
        removeMiddle(nodeCode);
        putMiddle(middle);
        
        for (UUID childId : middle.children) {
            LeafNode child = leafNodes.get(childId);
            child.parentCode = middle.nodeCode;
        }
        List<String> children = new ArrayList<>();
        List<String> codes = codeValuesTaken.get(digitSize + 1);
        if (codes != null) {
            children.addAll(codes);
        }
        for (String code : children) {
            MiddleNode child = getMiddle(code);
            if (child.parentCode.equals(nodeCode)) {
                updateNodeCodes(code, middle.nodeCode);
            }
        }
    }
    
    private String setRootCode(int DigitLength) {
        int multiplier = (int)(Math.pow(10, DigitLength));
        int code = (int)(Math.pow(10, DigitLength) * Math.random());
        if (code / (multiplier / 10) < 1) 
            code *= 10;
        return Integer.toString(code);
    }
    
    private void putMiddle(MiddleNode node) {
        Integer digitSize = node.nodeCode.length();
        if (middleNodes.get(digitSize) == null) {
            middleNodes.put(digitSize, new HashMap<String, MiddleNode>());
            codeValuesTaken.put(digitSize, new ArrayList<String>());
        }
        codeValuesTaken.get(digitSize).add(node.nodeCode);
        middleNodes.get(digitSize).put(node.nodeCode, node);
    }
    
    private void removeMiddle(String code) {
        Integer digitSize = code.length();
        middleNodes.get(digitSize).remove(code);
        codeValuesTaken.get(digitSize).remove(code);
    }
    
    private MiddleNode getMiddle(String code) {
        Integer digitSize = code.length();
        return middleNodes.get(digitSize).get(code);
    }
    
    //middlenode, just need to hold key and nodeCode
    //The nodes in between the root and each leafNode
    private class MiddleNode implements Node {
        private String parentCode;
        private String nodeCode;
        private List<UUID> children;
        private SecretKey key;
        private int numberOfChildren;
        private boolean exposed;
              
        private MiddleNode(String parentCode) {
            this.parentCode = parentCode;
            this.children = new ArrayList<>();
            this.exposed = false;
            this.numberOfChildren = 0;
            this.nodeCode = addRandomDigit(parentCode);
        }
        
        //ONLY for rootNode
        private MiddleNode() {
            this.numberOfChildren = 0;
            this.children = new ArrayList<>();
            this.exposed = false;
            this.nodeCode = setRootCode(numberOfCodeDigits);
        }
    }
    
    //leafNode, aka group members. Only need info that KeyServer needs
    //no need to have instance of every member (keep everything to a minimum)
    private class LeafNode implements Node {
        private final SecretKey key;
        private String parentCode;
        
        private LeafNode(String position, SecretKey key) {
            this.parentCode = position; 
            this.key = key;
        }
    }
}