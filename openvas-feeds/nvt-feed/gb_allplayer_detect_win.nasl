# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805100");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-11-21 09:52:53 +0530 (Fri, 21 Nov 2014)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ALLPlayer Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"This script detects the installed
  version of ALLPlayer.

  The script logs in via smb, searches for ALLPlayer in the registry
  and gets the version from registry or file.");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently 64bit application is not available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("ALLPlayer" >< appName && "Remote Control" >!< appName)
  {
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(insloc)
    {
      AllVer = fetch_file_version(sysPath:insloc, file_name:"ALLPlayer.exe");
      if(AllVer)
      {
        set_kb_item(name:"ALLPlayer/Win/Ver", value:AllVer);

        cpe = build_cpe(value:AllVer, exp:"^([0-9.]+)", base:"cpe:/a:allplayer:allplayer:");
        if(isnull(cpe))
          cpe = "cpe:/a:allplayer:allplayer";

        register_product(cpe:cpe, location:insloc);

        log_message(data: build_detection_report(app: appName,
                                                 version: AllVer,
                                                 install: insloc,
                                                 cpe: cpe,
                                                 concluded: AllVer));
      }
    }
  }
}
