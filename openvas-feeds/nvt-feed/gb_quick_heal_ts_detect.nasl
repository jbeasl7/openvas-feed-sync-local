# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811548");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-02 17:45:09 +0530 (Wed, 02 Aug 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Quick Heal Total Security Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Quick Heal Total Security.

  The script logs in via smb, searches for Quick Heal Total Security in the
  registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Quick Heal Total Security")){
    exit(0);
}

## Key is independent of platform
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Quick Heal Total Security\";

qhName = registry_get_sz(key:key, item:"DisplayName");

if("Quick Heal Total Security" >< qhName)
{
  qhPath = registry_get_sz(key:key, item:"InstallLocation");
  if(qhPath)
  {
    qhVer = fetch_file_version(sysPath: qhPath, file_name:"scanner.exe");
    if(qhVer)
    {
      set_kb_item(name:"QuickHeal/TotalSecurity6432/Installed", value:TRUE);
      set_kb_item(name:"QuickHeal/TotalSecurity/Ver", value:qhVer);
      register_and_report_cpe( app:qhName, ver:qhVer, base:"cpe:/a:quick_heal:total_security:", expr:"^([0-9.]+)", insloc:qhPath );
      ## 64 bit apps on 64 bit platform
      if("x64" >< os_arch) {
        set_kb_item(name:"QuickHeal/TotalSecurity64/Ver", value:qhVer);
        register_and_report_cpe( app:qhName, ver:qhVer, base:"cpe:/a:quick_heal:total_security:x64:", expr:"^([0-9.]+)", insloc:qhPath );
      }
    }
  }
}

exit(0);
