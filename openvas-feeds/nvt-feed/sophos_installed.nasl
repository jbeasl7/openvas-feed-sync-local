# SPDX-FileCopyrightText: 2005 Jason Haar
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12215");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Sophos Anti Virus Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Jason Haar");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "smb_enum_services.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");

  script_tag(name:"summary", value:"This plugin checks that the remote host
  has the Sophos Antivirus installed and that it is running.

  The script logs in via SMB, searches for Sophos Antivirus in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

services = get_kb_item("SMB/svcs");

key = "SOFTWARE\Sophos\SweepNT\";
if( registry_key_exists( key:key ) ) {
  version = registry_get_sz( key:key, item:"Version" );
}

if(!version)
{
  os_arch = get_kb_item("SMB/Windows/Arch");

  if("x86" >< os_arch){
    key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  } else if("x64" >< os_arch){
    key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
  }

  if(isnull(key)){
    exit(0);
  }

  foreach item (registry_enum_keys(key:key))
  {
    sophosName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Sophos Anti-Virus" >< sophosName)
    {
      sophosVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      sophosPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!sophosPath){
        sophosPath = "Unable to find the install location from registry";
      }

      if(sophosVer)
      {
        set_kb_item(name:"Sophos/Anti-Virus/Win/Installed", value:TRUE);
        set_kb_item(name:"Sophos/Anti-Virus/Win/Ver", value:sophosVer);
        register_and_report_cpe( app:"Sophos Anti-Virus", ver:sophosVer, base:"cpe:/a:sophos:anti-virus:", expr:"^([0-9.]+)", insloc:sophosPath );
      }
    }
  }
}

if((version || sophosVer) && services)
{
  if("[SWEEPSRV]" >!< services)
  {
    report = "
    The remote host has the Sophos antivirus installed, but it
    is not running.

    As a result, the remote host might be infected by viruses received by
    email or other means.

    Solution: Enable the remote AntiVirus and configure it to check for
    updates regularly.";
    log_message(data:report);
  }
}
