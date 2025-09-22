# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809011");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-08-29 13:05:30 +0530 (Mon, 29 Aug 2016)");
  script_name("Flexera InstallAnywhere Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"Detects the installed version of
  Flexera InstallAnywhere on Windows.

  The script logs in via smb, searches for InstallAnywhere in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  installName = registry_get_sz(key:key + item, item:"DisplayName");

  if(installName =~ "InstallAnywhere( 2015| 2014| 2013| 2012| 2011)?$")
  {
    installVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    installPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!installPath){
      installPath = "Unable to find the install location from registry";
    }

    set_kb_item(name:"InstallAnywhere/Win/Ver", value:installVer);
    register_and_report_cpe( app:"Flexera InstallAnywhere", ver:installVer, base:"cpe:/a:flexerasoftware:installanywhere:", expr:"^([0-9.]+)", insloc:installPath );
  }
}
