# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

##############################################################################
# CLASS: Win32_OperatingSystem
##############################################################################

function wmi_os_version()
{
  osVer = powershell_wmi_query(classname:"Win32_OperatingSystem", properties:"Version");

  if(isnull(osVer) || !osVer){
    return(0);
  }

  osVer = eregmatch(pattern:"[0-9]+\.[0-9]", string:osVer);
  if(osVer[0] == NULL){
    return(0);
  }
  return osVer[0];
}

function wmi_os_type()
{
  osType = powershell_wmi_query(classname:"Win32_OperatingSystem", properties:"ProductType");
  osType = eregmatch(pattern:"[0-9]", string:osType);

  if(isnull(osType) || !osType){
    return(0);
  }

  if(osType[0] == NULL){
    return(0);
  }
  return osType[0];
}

function wmi_os_sp()
{
  query = 'Select CSDVersion from Win32_OperatingSystem';

  # No direct variable access as the empty val result needs to be interpreted later
  spVer = powershell_wmi_query( query:query );

  if(isnull(spVer) || !spVer){
    return(0);
  }

  spVer = eregmatch(pattern:"Service Pack [0-9]", string:spVer);
  if(spVer[0] == NULL){
    return(1);  # Return 1 if OS without Service Pack.
  }
  return spVer[0];
}

function wmi_os_hotfix()
{
  hfList = powershell_wmi_query(classname:"Win32_QuickFixEngineering", properties:"HotfixID");

  if(isnull(hfList) || !hfList){
    return(0);
  }

  hfList = split(hfList, "\n", keep:0);
  if(hfList != NULL){
    return hf;
  }
  else return(0);
}

function wmi_os_buildnumber()
{
  buildVal = powershell_wmi_query(classname:"Win32_OperatingSystem", properties:"BuildNumber");

  if(isnull(buildVal) || !buildVal){
    return(0);
  }

  buildVal = eregmatch(pattern:"[0-9]+", string:buildVal);

  if(buildVal[0] != NULL){
    return buildVal[0];
  }
  else return(0);
}

function wmi_os_windir()
{
  winDir =  powershell_wmi_query(classname:"Win32_OperatingSystem", properties:"WindowsDirectory");

  if(isnull(winDir) || !winDir){
    return(0);
  }

  return winDir;
}

function wmi_os_sysdir()
{
  sysDir = powershell_wmi_query(classname:"Win32_OperatingSystem", properties:"SystemDirectory");

  if(isnull(sysDir) || !sysDir){
    return(0);
  }

  return sysDir;
}

function wmi_os_all(handle)
{
  query = 'Select * from Win32_OperatingSystem';

  winAll = powershell_wmi_query(query:query, as_list:TRUE);

  if(isnull(winAll) || !winAll){
    return(0);
  }

  return winAll;
}
