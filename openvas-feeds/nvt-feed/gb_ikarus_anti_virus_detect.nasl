# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112156");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-01-04 09:35:57 +0100 (Thu, 04 Jan 2018)");

  script_name("IKARUS anti.virus Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detection of the installed version of IKARUS anti.virus.

  The script logs in via SMB, searches for the installation of 'IKARUS anti.virus' in the registry
  and tries to obtain the version information.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");

if(!os_arch) {
  exit(0);
}

if("x86" >< os_arch) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
} else if("x64" >< os_arch) {
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key)) {
  product = registry_get_sz(key:key + item, item:"DisplayName");

  if("IKARUS anti.virus" >< product) {
    set_kb_item(name:"ikarus/anti.virus/detected", value:TRUE);
    version = "unknown";
    installed = TRUE;

    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    path = registry_get_sz(key:key + item, item:"InstallLocation");

    break;
  }
}

if(installed) {

  if(ver) {
    version = ver;
    set_kb_item(name:"ikarus/anti.virus/version", value:version);
  }

  if(!path) {
    # InstallLocation not found, try getting MainPath from different registry entry
    if(!path = registry_get_sz(key:"SOFTWARE\Ikarus\guardx", item:"MainPath")) {
      path = "Could not get the install location from the registry";
    }
  }

  register_and_report_cpe(app:"IKARUS anti.virus", ver:version, base:"cpe:/a:ikarus:anti.virus:", expr:"^([0-9.]+)", insloc:path);
}

exit(0);
