# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811732");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-09-08 15:22:17 +0530 (Fri, 08 Sep 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("DocuWorks Viewer Light Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  DocuWorks Viewer Light.

  The script logs in via smb, searches for 'Xerox DocuWorks Viewer Light' string and
  gets the version from 'DisplayVersion' string from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

## Application confirmation, Only 32-bit application is available
if(!registry_key_exists(key:"SOFTWARE\FujiXerox\DocuWorks Viewer Light"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\FujiXerox\DocuWorks Viewer Light")){
    exit(0);
  }
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

## Enumerate all keys
foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Xerox DocuWorks Viewer Light" >< appName)
  {
   appVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(appVer)
    {
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc){
        insloc = "Could not find install location.";
      }
      set_kb_item(name:"DocuWorks/Viewer/Light/Win/Ver", value:appVer);

      cpe = build_cpe(value:appVer, exp:"([0-9.]+)", base:"cpe:/a:fujixerox:docuworks_viewer_light:");
      if(isnull(cpe))
        cpe = "cpe:/a:fujixerox:docuworks_viewer_light";

      register_product(cpe:cpe, location:insloc);

      log_message(data: build_detection_report(app: "DocuWorks Viewer Light",
                                               version: appVer,
                                               install: insloc,
                                               cpe: cpe,
                                               concluded: appVer));
      exit(0);
    }
  }
}
exit(0);
