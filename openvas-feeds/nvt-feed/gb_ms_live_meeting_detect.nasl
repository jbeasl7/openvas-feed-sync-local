# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804597");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-06-11 14:04:01 +0530 (Wed, 11 Jun 2014)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Live Meeting Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Live Meeting on Windows.

The script logs in via smb, searches for Live Meeting in the
registry and gets the version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Live Meeting"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Live Meeting")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently Microsoft Office Live Meeting 64bit application is not available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Microsoft Office Live Meeting" >< appName)
  {
    appVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(appVer)
    {
      appPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!appPath){
        appPath = "Could not find the install location from registry";
      }

      set_kb_item(name:"MS/OfficeLiveMeeting/Ver", value:appVer);

      cpe = build_cpe(value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:office_live_meeting:");
      if(isnull(cpe))
        cpe = "cpe:/a:microsoft:office_live_meeting";

      register_product(cpe:cpe, location:appPath);

      log_message(data: build_detection_report(app:appName,
                                               version:appVer, install:appPath,
                                               cpe:cpe, concluded: appVer));
    }
  }
}
