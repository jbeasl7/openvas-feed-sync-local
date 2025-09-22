# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814312");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-10-12 09:49:05 +0530 (Fri, 12 Oct 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Technical Communication Suite Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"Detects the installed version of Adobe
  Technical Communication Suite on Windows.

  The script logs in via smb, searches for Adobe Technical Communication
  Suite and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
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
 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  if( eregmatch( pattern:"Adobe Technical Communication Suite [0-9].*", string:appName ))
  {
    tcsPath = registry_get_sz(key:key + item, item:"InstallPath");
    if(!tcsPath){
      tcsPath = "Did not find install path from registry.";
    }

    tcsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!tcsVer){
      exit(0);
    }

    set_kb_item(name:"AdobeTCS/Win/Ver", value:tcsVer);
    cpe = build_cpe(value:tcsVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:tcs:");
    if(isnull(cpe)){
      cpe = "cpe:/a:adobe:tcs";
    }

    register_product(cpe: cpe, location: tcsPath);
    log_message(data: build_detection_report(app: "Adobe Technical Communication Suite",
                                             version: tcsVer,
                                             install: tcsPath,
                                             cpe: cpe,
                                             concluded: tcsVer));
  }
}

exit(0);
