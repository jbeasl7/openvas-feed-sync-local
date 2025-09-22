# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112295");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-06-06 12:56:06 +0200 (Wed, 06 Jun 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Autopsy Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detection of the installed version of Autopsy on Windows.

  The script logs in via SMB and searches the registry for Autopsy installations,
  version and location information.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\The Sleuth Kit") && !registry_key_exists(key:"SOFTWARE\The Sleuth Kit"))
  exit( 0 );

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}
else if("x64" >< os_arch) {
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)) exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {
    name = registry_get_sz(key:key + item, item:"DisplayName");

    if(name =~ "^Autopsy") {
      version = registry_get_sz(key:key + item, item:"DisplayVersion");
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");

      if(!version) {
        if(!insloc) {
          insloc = "Unable to find the install location";
        } else {
          version = fetch_file_version(sysPath:insloc + "bin", file_name:"autopsy.exe");
        }
      }

      if(version) {
        set_kb_item(name:"autopsy/win/detected", value:TRUE);

        base = "cpe:/a:sleuthkit:autopsy:";

        if("64" >< os_arch && "Wow6432Node" >!< key)
          base += "x64:";

        register_and_report_cpe(app:"Autopsy", ver:version, concluded:version, base:base, expr:"^([0-9.]+)", insloc:insloc);
      }
    }
  }
}

exit(0);
