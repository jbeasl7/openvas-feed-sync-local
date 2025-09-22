# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801149");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Yahoo! Messenger Version Detection");

  script_tag(name:"summary", value:"This script detects the installed version of Yahoo! Messenger.

The script logs in via smb, search for the product name in the registry, gets
application Path from the registry and fetches the version from exe file.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
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
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Yahoo! Messenger");
  key_list2 = make_list("SOFTWARE\Yahoo\pager");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Yahoo! Messenger");
  key_list2 = make_list("SOFTWARE\Wow6432Node\Yahoo\pager");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  ymsgName = registry_get_sz(key:key, item:"DisplayName");

  if("Yahoo! Messenger" >< ymsgName)
  {
    ymsgPath = registry_get_sz(key:key, item:"DisplayIcon");
    ymsgPath = ymsgPath - "\YahooMessenger.exe,-0";

    foreach key1 (key_list2)
    {
      ymsgVer = registry_get_sz(key:key1, item:"ProductVersion");
      if(!ymsgVer)
      {
        ymsgVer = fetch_file_version(sysPath:ymsgPath, file_name:"YahooMessenger.exe");
      }
    }

    if(ymsgVer)
    {
      set_kb_item(name:"YahooMessenger/Ver", value:ymsgVer);
      register_and_report_cpe( app:"Yahoo Messenger", ver:ymsgVer, base:"cpe:/a:yahoo:messenger:", expr:"^([0-9.]+)", insloc:ymsgPath );
    }
  }
}
