# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801263");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Trend Micro Internet Security Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Trend Micro Internet Security on Windows.

The script logs in via smb, searches for Trend Micro Internet Security in the
registry and gets the version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
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

## Application is not having separate installer for 64 and 32 bit
if(!registry_key_exists(key:"SOFTWARE\TrendMicro\")){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  AppName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Trend Micro"  >< AppName && "Internet Security" >< AppName)
  {
    AppVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(AppVer != NULL)
    {
      insLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insLoc){
        insLoc = "Could not find the install location from registry";
      }

      set_kb_item(name:"TrendMicro/IS/Installed", value:TRUE);

      if("64" >< os_arch) {
        set_kb_item(name:"TrendMicro/IS64/Ver", value:AppVer);
        register_and_report_cpe( app:AppName, ver:AppVer, concluded:AppName, base:"cpe:/a:trendmicro:internet_security:x64:", expr:"^([0-9.]+)", insloc:insLoc );
      } else {
        set_kb_item(name:"TrendMicro/IS/Ver", value:AppVer);
        register_and_report_cpe( app:AppName, ver:AppVer, concluded:AppName, base:"cpe:/a:trendmicro:internet_security:", expr:"^([0-9.]+)", insloc:insLoc );
      }
    }
  }
}
