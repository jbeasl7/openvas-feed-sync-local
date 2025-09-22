# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96006");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Removable media deactivated - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"This Script checks whether drives disables that containing removable media,
  such as USB ports, CD-ROM drives, Floppy Disk drives and high capacity LS-120 floppy drives.");

  exit(0);
}

include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/CD_driver_start", value:"error");
  set_kb_item(name:"WMI/FD_driver_start", value:"error");
  set_kb_item(name:"WMI/SF_driver_start", value:"error");
  set_kb_item(name:"WMI/USB_driver_start", value:"error");
  set_kb_item(name:"WMI/StorageDevicePolicies", value:"error");
  set_kb_item(name:"WMI/StorageDevicePolicies/log", value:"No access to SMB host. Firewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/CD_driver_start", value:"error");
  set_kb_item(name:"WMI/FD_driver_start", value:"error");
  set_kb_item(name:"WMI/SF_driver_start", value:"error");
  set_kb_item(name:"WMI/USB_driver_start", value:"error");
  set_kb_item(name:"WMI/StorageDevicePolicies", value:"error");
  set_kb_item(name:"WMI/StorageDevicePolicies/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

STARTCDKEY = wmi_reg_enum_value(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\Cdrom");
STARTFDKEY = wmi_reg_enum_value(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\Flpydisk");
STARTSFKEY = wmi_reg_enum_value(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\Sfloppy");

if(!STARTCDKEY) startcd = "inapplicable";
if(!STARTFDKEY) startfd = "inapplicable";
if(!STARTSFKEY) startsf = "inapplicable";


sdp = wmi_reg_get_dword_val(wmi_handle:handle, key:"System\CurrentControlSet\Control\StorageDevicePolicies", val_name:"WriteProtect");

if (!startcd) startcd = wmi_reg_get_dword_val(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\Cdrom", val_name:"start");

if (!startfd) startfd = wmi_reg_get_dword_val(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\Flpydisk", val_name:"start");

if (!startsf) startsf = wmi_reg_get_dword_val(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\Sfloppy", val_name:"start");

startusb = wmi_reg_get_dword_val(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\USBSTOR", val_name:"start");

if (!startusb) startusb = "inapplicable";
if(!sdp) sdp = "off";

if(startcd == 4){
  set_kb_item(name:"WMI/CD_driver_start", value:"off");
} else if (startcd >< "inapplicable"){
  set_kb_item(name:"WMI/CD_driver_start", value:startcd);
} else {
  set_kb_item(name:"WMI/CD_driver_start", value:"on");
}

if(startfd == 4){
  set_kb_item(name:"WMI/FD_driver_start", value:"off");
} else if (startfd >< "inapplicable"){
  set_kb_item(name:"WMI/FD_driver_start", value:startfd);
} else {
  set_kb_item(name:"WMI/FD_driver_start", value:"on");
}

if(startsf == 4){
  set_kb_item(name:"WMI/SF_driver_start", value:"off");
} else if (startsf >< "inapplicable"){
  set_kb_item(name:"WMI/SF_driver_start", value:startsf);
} else {
  set_kb_item(name:"WMI/SF_driver_start", value:"on");
}

if(startusb == 4){
  set_kb_item(name:"WMI/USB_driver_start", value:"off");
} else if (startusb >< "inapplicable"){
  set_kb_item(name:"WMI/USB_driver_start", value:startusb);
} else {
  set_kb_item(name:"WMI/USB_driver_start", value:"on");
}

if(sdp == 1){
  set_kb_item(name:"WMI/StorageDevicePolicies", value:"on");
} else {
  set_kb_item(name:"WMI/StorageDevicePolicies", value:"off");
}

wmi_close(wmi_handle:handle);

exit(0);
