# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

##############################################################################
# CLASS: Win32_SystemAccount / Win32_UserAccount / Win32_Group / Win32_GroupUser Functions
#
# - powershell_wmi_user_sysaccount              - Queries System Account Information
# - powershell_wmi_user_useraccount             - Lists the information of User Account
# - powershell_wmi_user_group                   - Returns the Group of target system
# - powershell_wmi_user_groupuser               - Gets associated Groups for all users
# - powershell_wmi_user_is_useraccount_disabled - Returns Disabled=True, Enabled=False
# - powershell_wmi_user_is_userpass_changeable  - Returns Cangeable=True, else False
# - powershell_wmi_user_is_userpass_expires     - Returns PasswordExpires=True, else False
# - powershell_wmi_user_is_user_locked          - Returns all locked users
# - powershell_wmi_local_users                  - Returns all local users
#
##############################################################################

# Ex: usrName = "System" or no value for all users
function powershell_wmi_user_sysaccount(usrName){

  local_var usrName;
  local_var cmd,usrList;

  if(!usrName){
    cmd = "get-wmiobject -query 'Select SID from Win32_SystemAccount'";
  }
  else {
    cmd = "get-wmiobject -query 'Select * from Win32_SystemAccount Where Name = ''" + usrName + "'''";
  }

  usrList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< usrList) || !usrList){
    return(0);
  }

  return usrList;
}

# Ex: usrName = "Administrator" or no value for all users
function powershell_wmi_user_useraccount(usrName){

  local_var usrName;
  local_var cmd,usrList;

  if(!usrName){
    cmd = "get-wmiobject -query 'Select SID from Win32_UserAccount'";
  }
  else {
    cmd = "get-wmiobject -query 'Select * from Win32_UserAccount Where Name = ''" + usrName + "'''";
  }

  usrList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< usrList) || !usrList){
    return(0);
  }

  return usrList;
}

# Ex: grpName = "Administrators" or no value for all groups
function powershell_wmi_user_group(grpName){

  local_var grpName;
  local_var cmd,grpList;

  if(!usrName){
    cmd = "get-wmiobject -query 'Select SID from Win32_Group'";
  }
  else {
    cmd = "get-wmiobject -query 'Select * from Win32_Group Where Name = ''" + grpName + "'''";
  }

  grpList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< grpList) || !grpList){
    return(0);
  }

  return grpList;
}

function powershell_wmi_user_groupuser(){

  cmd = "get-wmiobject -query 'Select * from Win32_GroupUser'";

  grpList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< grpList) || !grpList){
    return(0);
  }

  return grpList;
}

# Ex: usrName = "Administrator" or no value for all users
function powershell_wmi_user_is_useraccount_disabled(usrName){

  local_var usrName;
  local_var cmd,usrList;

  if(!usrName){
    cmd = "get-wmiobject -query 'Select Disabled from Win32_UserAccount'";
  }else{
    cmd = "get-wmiobject -query 'Select Disabled from Win32_UserAccount Where Name = ''" + usrName + "'''";
  }

  usrList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< usrList) || !usrList){
    return(0);
  }

  return usrList;
}

# Ex: usrName = "Administrator" or no value for all users
function powershell_wmi_user_is_userpass_changeable(usrName){

  local_var usrName;
  local_var cmd,usrList;

  if(!usrName){
    cmd = "get-wmiobject -query 'Select PasswordChangeable from Win32_UserAccount'";
  }
  else {
    cmd = "get-wmiobject -query 'Select PasswordChangeable from Win32_UserAccount Where Name = ''" + usrName + "'''";
  }

  usrList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< usrList) || !usrList){
    return(0);
  }

  return usrList;
}

# Ex: usrName = "Administrator" or no value for all users
function powershell_wmi_user_is_userpass_expires(usrName){

  local_var usrName;
  local_var cmd,usrList;

  if(!usrName){
    cmd = "get-wmiobject -query 'Select PasswordExpires from Win32_UserAccount'";
  }
  else {
    cmd = "get-wmiobject -query 'Select PasswordExpires from Win32_UserAccount Where Name = ''" + usrName + "'''";
  }

  usrList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< usrList) || !usrList){
    return(0);
  }

  return usrList;
}

# Ex: usrName = "Administrator" or no value for all users
function powershell_wmi_user_is_user_locked(usrName){

  local_var usrName;
  local_var cmd,usrList;

  if(!usrName){
    cmd = "get-wmiobject -query 'Select Lockout from Win32_UserAccount'";
  }
  else {
    cmd = "get-wmiobject -query 'Select Lockout from Win32_UserAccount Where Name = ''" + usrName + "'''";
  }

  usrList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< usrList) || !usrList){
    return(0);
  }

  return usrList;
}

function powershell_wmi_local_users(){

  cmd = "get-wmiobject -query 'Select * from Win32_UserAccount Where LocalAccount=true'";

  LocalUserList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< LocalUserList) || !LocalUserList){
    return(0);
  }

  return LocalUserList;
}

##############################################################################