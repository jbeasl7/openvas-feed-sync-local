# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803748");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-28 10:27:23 +0530 (Wed, 28 Aug 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("RSA Authentication Agent Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of RSA Authentication Agent.

The script logs in via smb, searches for RSA Authentication Agent and gets
the version from 'DisplayVersion' string in registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

## RSA Authentication Agent for IIS
if(!registry_key_exists(key:"SOFTWARE\RSA\RSA Authentication Agent"))
{
  if(!registry_key_exists(key:"SOFTWARE\RSAACEAgents\Web")){
    exit(0);
  }
}

key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");

if(isnull(key_list)){
  exit(0);
}

foreach key(key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    rsaName = registry_get_sz(key:key + item, item:"DisplayName");
    if("RSA Authentication Agent" >< rsaName)
    {
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc){
        insloc = "Could not find the install location from registry";
      }
    }

    rsaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!rsaVer){
      continue;
    }

    if("RSA Authentication Agent" >< rsaName && "Web for IIS" >!< rsaName &&
        registry_key_exists(key:"SOFTWARE\RSA\RSA Authentication Agent"))
    {
      set_kb_item(name:"RSA/AuthenticationAgent6432/Installed", value:rsaVer);
      set_kb_item(name:"RSA/AuthenticationAgent/Ver", value:rsaVer);
      register_and_report_cpe( app:"RSA Authentication Agent", ver:rsaVer, concluded:rsaVer, base:"cpe:/a:emc:rsa_authentication_agent:", expr:"^([0-9.]+)", insloc:insloc );
      if("x64" >< os_arch) {
        set_kb_item(name:"RSA/AuthenticationAgent64/Ver", value:rsaVer);
        register_and_report_cpe( app:"RSA Authentication Agent", ver:rsaVer, concluded:rsaVer, base:"cpe:/a:emc:rsa_authentication_agent:x64:", expr:"^([0-9.]+)", insloc:insloc );
      }
      continue;
    }

    ## RSA Authentication Agent for IIS
    if("RSA Authentication Agent for Web for IIS" >< rsaName && registry_key_exists(key:"SOFTWARE\RSAACEAgents\Web"))
    {
      set_kb_item(name:"RSA/AuthenticationAgentWebIIS6432/Installed", value:TRUE);
      set_kb_item(name:"RSA/AuthenticationAgentWebIIS/Ver", value:rsaVer);
      register_and_report_cpe( app:"RSA Authentication Agent", ver:rsaVer, concluded:rsaVer, base:"cpe:/a:emc:rsa_authentication_agent_iis:", expr:"^([0-9.]+)", insloc:insloc );

      if("x64" >< os_arch) {
        set_kb_item(name:"RSA/AuthenticationAgentWebIIS64/Ver", value:rsaVer);
        register_and_report_cpe( app:"RSA Authentication Agent", ver:rsaVer, concluded:rsaVer, base:"cpe:/a:emc:rsa_authentication_agent_iis:x64:", expr:"^([0-9.]+)", insloc:insloc );
      }
    }
  }
}
