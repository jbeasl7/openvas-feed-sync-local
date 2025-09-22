# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814323");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-11-22 11:16:44 +0530 (Thu, 22 Nov 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Yammer Desktop Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Yammer Desktop
  on Windows.

  The script logs in via smb, searches for Telegram Desktop and gets the
  version from registry.");

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

if("x64" >< osArch){
 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x86" >< osArch){
 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key, type:"HKCU")){
  exit(0);
}

foreach item (registry_enum_keys(key:key, type:"HKCU"))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName", type:"HKCU");
  if("Yammer" >< appName)
  {
    yamPath = registry_get_sz(key:key + item, item:"InstallLocation", type:"HKCU");
    yamVer = registry_get_sz(key:key + item, item:"DisplayVersion", type:"HKCU");
    if(!yamVer){
      exit(0);
    }
    set_kb_item(name:"Microsoft/Yammer/Win/Ver", value:yamVer);

    cpe = build_cpe(value:yamVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:yammer:");
    if(isnull(cpe))
       cpe = "cpe:/a:microsoft:yammer";

    register_product(cpe: cpe, location: yamPath, service:"smb-login", port:0);

    report =  build_detection_report(app: "Yammer",
                                 version: yamVer,
                                 install: yamPath,
                                     cpe: cpe,
                               concluded: yamVer);
    if(report){
      log_message( port:0, data:report );
    }
  }
}
exit(0);
