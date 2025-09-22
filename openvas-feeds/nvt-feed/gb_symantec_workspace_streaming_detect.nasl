# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805541");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-04-28 18:51:34 +0530 (Tue, 28 Apr 2015)");
  script_name("Symantec Workspace Streaming (SWS) Agent Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Symantec Workspace Streaming Agent.

  The script logs in via smb, searches for 'Symantec Workspace Streaming Agent'
  in the registry and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");


os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Key is same for 32 bit and 64 bit platform
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  agentName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Symantec Workspace Streaming Agent" >< agentName)
  {
    agentVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    agentPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!agentPath)
    {
      agentPath = registry_get_sz(key:key + item, item:"InstallSource");
      if(!agentPath){
        agentPath = "Could not find the install location from registry";
      }
    }

    if(agentVer) {
      set_kb_item(name:"Symantec/Workspace/Streaming/Agent/Win6432/Installed", value:TRUE);
      if("64" >< os_arch) {
        set_kb_item(name:"Symantec/Workspace/Streaming/Agent/Win64/Ver", value:agentVer);
        register_and_report_cpe( app:agentName, ver:agentVer, base:"cpe:/a:symantec:workspace_streaming:x64:", expr:"^([0-9.]+)", insloc:agentPath );
      } else {
        set_kb_item(name:"Symantec/Workspace/Streaming/Agent/Win/Ver", value:agentVer);
        register_and_report_cpe( app:agentName, ver:agentVer, base:"cpe:/a:symantec:workspace_streaming:", expr:"^([0-9.]+)", insloc:agentPath );
      }
    }
    exit(0);
  }
}
