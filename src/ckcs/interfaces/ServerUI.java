package ckcs.interfaces;

import ckcs.classes.GroupController;

public interface ServerUI {
    
    //GroupController class calls this method on the UI everytime a state changes in the GroupController class
    //the implementing UI extracts state data from this method
    public void updateState(GroupController.InterfaceData data);
}
