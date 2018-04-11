package ckcs.interfaces;

import ckcs.classes.GroupMember;

public interface MemberUI {
    
    //GroupMember class calls this method on the UI everytime a state changes in the GroupMember class
    //the implementing UI extracts member state data from this method
    public void updateState(GroupMember.InterfaceData data);
}
