# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814058");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-09-28 14:56:21 +0530 (Fri, 28 Sep 2018)");
  script_name("Mercurial Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Mercurial.

  The script logs in via smb, searches registry for Mercurial and gets the version
  from 'DisplayVersion' string.");

  script_tag(name:"qod_type", value:"registry");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    merName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Mercurial" >< merName)
    {
      merVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      merPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!merPath) {
        merPath = "Unable to find the install location from registry";
      }

      set_kb_item(name:"Mercurial/Win/Installed", value:TRUE);
      register_and_report_cpe( app:"Mercurial", ver:merVer, base:"cpe:/a:mercurial:mercurial:", expr:"^([0-9.]+)", insloc:merPath );

      if("64" >< os_arch && "Wow6432Node" >!< key) {
        set_kb_item(name:"Mercurial64/Win/Ver", value:merVer);
        register_and_report_cpe( app:"Mercurial", ver:merVer, base:"cpe:/a:mercurial:mercurial:x64:", expr:"^([0-9.]+)", insloc:merPath );
      }
    }
  }
}
exit(0);
