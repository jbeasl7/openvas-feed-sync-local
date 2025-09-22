# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902293");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-28 13:43:25 +0100 (Mon, 28 Feb 2011)");
  script_name("Metasploit Framework Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script finds the installed Metasploit Framework version.

  The script logs in via smb, searches for Metasploit in the registry and gets
  the version from 'DisplayVersion' string from the registry.");

  script_tag(name:"qod_type", value:"registry");

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

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}


foreach key(key_list)
{
  foreach item(registry_enum_keys(key:key))
  {
    msName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Metasploit" >< msName)
    {
      msVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(msVer)
      {
        msPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!msPath){
          msPath = "Could not find the install location from registry";
        }

        set_kb_item(name:"metasploit/framework/detected", value:TRUE);
        set_kb_item(name:"Metasploit/Framework/Win/Ver", value:msVer);

        cpe = build_cpe(value:msVer, exp:"^([0-9.]+)", base:"cpe:/a:metasploit:metasploit_framework:");
        if(!cpe)
          cpe = "cpe:/a:metasploit:metasploit_framework";

        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"Metasploit/Framework64/Win/Ver", value:msVer);

          cpe = build_cpe(value:msVer, exp:"^([0-9.]+)", base:"cpe:/a:metasploit:metasploit_framework:x64:");
          if(!cpe)
            cpe = "cpe:/a:metasploit:metasploit_framework:x64";

        }
        register_product(cpe:cpe, location:msPath, port:0, service:"smb-login");

        log_message(data:build_detection_report(app:"Metasploit Framework",
                                                version:msVer,
                                                install:msPath,
                                                cpe:cpe,
                                                concluded:msVer));
      }
    }
  }
}
