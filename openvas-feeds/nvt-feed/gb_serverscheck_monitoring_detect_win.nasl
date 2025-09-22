# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107365");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-11-10 14:45:11 +0100 (Sat, 10 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ServersCheck Monitoring Software Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of ServersCheck Monitoring Software for Windows.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if (!os_arch)
  exit(0);

if ("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if ("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list)) exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

  # ServersCheck Monitoring Software 14.3.2
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  version = "unknown";
  location = "unknown";

  if(!appName || appName !~ "ServersCheck Monitoring Software") continue;
  loc = registry_get_sz(key:key + item, item:"InstallLocation");
  if(loc) location = loc;

  ver = eregmatch(string:appName, pattern:"([0-9]+\.[0-9]+\.[0-9])$" );
  if(ver[1]) version = ver[1];

  set_kb_item(name:"serverscheck/monitoring_software/win/detected", value:TRUE);
  set_kb_item(name:"serverscheck/monitoring_software_or_server/detected", value:TRUE);
  set_kb_item(name:"serverscheck/monitoring_software/win/ver", value:version);

  register_and_report_cpe(app:"ServersCheck Monitoring Software", ver:version, concluded:appName,
                          base:"cpe:/a:serverscheck:monitoring_software:", expr:"^([0-9.]+)", insloc:location);
  exit(0);
  }
}
exit(0);
