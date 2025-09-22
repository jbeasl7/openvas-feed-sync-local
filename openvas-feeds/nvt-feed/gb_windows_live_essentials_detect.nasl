# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803603");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-15 14:11:55 +0530 (Wed, 15 May 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Windows Live Essentials Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Windows Live Essentials on Windows.

The script logs in via smb, searches for Windows Live Essentials in the
registry, gets the from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinLiveSuite\") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WinLiveSuite\")){
  exit(0);
}

if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinLiveSuite\";
}

else if("x64" >< osArch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinLiveSuite\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WinLiveSuite\");
}

foreach key (key_list)
{
  wName = registry_get_sz(key:key, item:"DisplayName");
  if("Windows Live Essentials" >< wName)
  {
    version = registry_get_sz(key:key, item:"DisplayVersion");
    if(version)
    {
      path = registry_get_sz(key:key, item:"InstallLocation");
      if(path)
      {
        set_kb_item(name:"Windows/Essentials6432/Installed", value:TRUE);
        if("x64" >< osArch && "Wow6432Node" >!< key) {
          set_kb_item(name:"Windows/Essentials64/Ver", value:version);
          register_and_report_cpe( app:"Windows Live Essentials", ver:version, base:"cpe:/a:microsoft:windows_essentials:x64:", expr:"^([0-9.]+)", insloc:path );
        } else {
          set_kb_item(name:"Windows/Essentials/Ver", value:version);
          register_and_report_cpe( app:"Windows Live Essentials", ver:version, base:"cpe:/a:microsoft:windows_essentials:", expr:"^([0-9.]+)", insloc:path );
        }
      }
    }
  }
}
