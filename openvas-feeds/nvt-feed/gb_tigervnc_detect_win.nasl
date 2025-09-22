# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801897");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("TigerVNC Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of TigerVNC.

The script logs in via smb, searches for TigerVNC in the registry and
gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
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

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"DisplayName");

    if("TigerVNC" >< appName)
    {
      tigerVncVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(tigerVncVer)
      {
        appLoc = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!appLoc){
          appLoc = "Could not find the install location from registry";
        }
        set_kb_item(name:"TigerVNC6432/Win/Installed", value:TRUE);
        set_kb_item(name:"TigerVNC/Win/Ver", value:tigerVncVer);
        register_and_report_cpe( app:appName, ver:tigerVncVer, base:"cpe:/a:tigervnc:tigervnc:", expr:"^([0-9.]+)", insloc:appLoc );

        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"TigerVNC64/Win/Ver", value:tigerVncVer);
          register_and_report_cpe( app:appName, ver:tigerVncVer, base:"cpe:/a:tigervnc:tigervnc:x64:", expr:"^([0-9.]+)", insloc:appLoc );
        }
      }
    }
  }
}
