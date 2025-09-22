# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107468");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-19 10:45:42 +0100 (Sat, 19 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Rockwell Windows Firewall Configuration Utility Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Rockwell Windows Firewall Configuration Utility.");

  script_xref(name:"URL", value:"https://www.rockwellautomation.com");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  location = "C:\Program Files\Common Files\Rockwell\WFCU\";
} else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  location = "C:\Program Files (x86)\Common Files\Rockwell\WFCU\";
}

if(isnull(key_list))
  exit(0);

foreach key(key_list) {
  foreach item(registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if(!appName || appName !~ "Rockwell Windows Firewall Configuration Utility")
      continue;

    version = "unknown";
    concluded = appName;

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc)
      location = loc;

    version = registry_get_sz(key:key + item, item:"DisplayVersion");

    set_kb_item(name:"rockwellautomation/windows_fw_conf_utility/win/detected", value:TRUE);

    register_and_report_cpe(app:appName, ver:version, concluded:concluded,
                            base:"cpe:/a:rockwellautomation:windows_fw_conf_utility:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
    exit(0);
  }
}

exit(0);
