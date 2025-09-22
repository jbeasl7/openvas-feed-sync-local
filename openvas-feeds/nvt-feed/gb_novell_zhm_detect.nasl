# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801644");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Novell ZENworks Handheld Management Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Novell ZENworks Handheld Management
on Windows.

The script logs in via smb, searches for ZENworks Handheld Management Server
in the registry and gets the version from the registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

if(!registry_key_exists(key:"SOFTWARE\Novell\ZENworks\Handheld Management\Server"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Novell\ZENworks\Handheld Management\Server")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Novell\ZENworks\Handheld Management\Server\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Novell\ZENworks\Handheld Management\Server\";
}

AppName = registry_get_sz(key:key, item:"Display Name");
if("ZENworks Handheld Management Server" >< AppName)
{
  AppVer = registry_get_sz(key:key, item:"Version");
  if(AppVer != NULL)
  {
    appPath = registry_get_sz(key:key, item:"InstallPath");
    if(!appPath){
      appPath = "Could not find the install Location from registry";
    }

    set_kb_item(name:"Novell/ZHM/Ver", value:AppVer);

    cpe = build_cpe(value:AppVer, exp:"^([0-9.]+)", base:"cpe:/a:novell:zenworks_handheld_management:");
    if(isnull(cpe))
      cpe = "cpe:/a:novell:zenworks_handheld_management";

    register_product(cpe:cpe, location:appPath);

    log_message(data: build_detection_report(app: AppName,
                                               version: AppVer,
                                               install: appPath,
                                               cpe: cpe,
                                               concluded: AppVer));
    exit(0);
  }
}

exit(0);
