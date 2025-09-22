# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814768");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-03-13 18:05:59 +0530 (Wed, 13 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Visual Studio Code Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of Microsoft Visual Studio Code for Windows.");

  script_tag(name:"qod_type", value:"registry");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("cpe.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if ("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if ("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list)) exit(0);

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Microsoft Visual Studio Code" >< appName)
    {

      version = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(!version){
        version = "Unknown";
      }

      set_kb_item(name:"microsoft_visual_studio_code/version", value:version);
      set_kb_item(name:"microsoft_visual_studio_code/installed", value:TRUE);

      location = registry_get_sz(key:key + item, item:"Inno Setup: App Path");
      if(!location){
        location = "Unable to find the install location from registry";
      }
      else {
        set_kb_item(name:"microsoft_visual_studio_code/location", value:location);
      }
      register_and_report_cpe(app:appName, ver:version, concluded:appName + " " + version,
                          base:"cpe:/a:microsoft:visual_studio_code:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
      exit(0);
    }
  }
}
exit(0);
