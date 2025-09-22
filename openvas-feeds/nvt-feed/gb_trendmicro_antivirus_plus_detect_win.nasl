# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813332");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-05-08 13:30:09 +0530 (Tue, 08 May 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Trend Micro Antivirus Plus Security Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"Detection of installed version
  of Trend Micro Antivirus Plus on Windows.

  The script logs in via smb, searches for Trend Micro Antivirus Plus in the
  registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

## Application is not having separate installer for 64 and 32 bit
if(!registry_key_exists(key:"SOFTWARE\TrendMicro\")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  AppName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Trend Micro Antivirus+" >< AppName)
  {
    AppVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(AppVer != NULL)
    {
      insLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insLoc){
        insLoc = "Could not find the install location from registry";
      }

      set_kb_item(name:"TrendMicro/AV/Installed", value:TRUE);
      set_kb_item(name:"TrendMicro/AV/Ver", value:AppVer);
      register_and_report_cpe( app:AppName, ver:AppVer, base:"cpe:/a:trendmicro:antivirus\+:", expr:"^([0-9.]+)", insloc:insLoc );

      if("64" >< osArch)
      {
        set_kb_item(name:"TrendMicro/AV64/Ver", value:AppVer);
        register_and_report_cpe( app:AppName, ver:AppVer, base:"cpe:/a:trendmicro:antivirus\+:x64:", expr:"^([0-9.]+)", insloc:insLoc );
      }
    }
  }
}

exit(0);
