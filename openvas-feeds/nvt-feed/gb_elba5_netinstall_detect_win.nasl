# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107441");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-08 16:13:29 +0100 (Tue, 08 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("RACON Software ELBA5 Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of RACON Software ELBA5.");

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
} else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list))
  exit(0);

foreach key(key_list) {
  foreach item(registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if(!appName || appName !~ "ELBA5")
      continue;

    set_kb_item(name:"racon_software/elba/win/detected", value:TRUE);

    split = split(appName, sep:" ");
    appName = split[0];

    version = "unknown";
    concluded = appName;
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc) {
      location = loc;

      path = location + '\\properties\\config.properties.defaults';

      version_info = smb_read_file(fullpath:path, offset:0, count:3000);
      if(version_info) {

        versq = eregmatch(pattern:"VERSION=([0-9]+)", string:version_info);
        if(versq) {
          concluded += " " + versq[0];
          vers = versq[1];
        }

        revq = eregmatch(pattern:"SUBVERSION=([A-Z])0*([1-9]+)", string:version_info);
        if(revq) {
          concluded += " " + revq[0];
          rev = revq[1] + revq[2];
        }

        if(vers)
          _vers = eregmatch(string:vers, pattern:"([0-9])([0-9])([0-9])([0-9])");

        if(_vers)
          version = _vers[1] + "." + _vers[2] + "." + _vers[3] + "." + _vers[4] + " " + rev;
      }
    }

    register_and_report_cpe(app:appName, ver:version, concluded:concluded,
                            base:"cpe:/a:racon_software:elba5:", expr:"^([0-9.]+) ?([A-Z0-9]+)?", insloc:location, regService:"smb-login", regPort:0);
    exit(0);
  }
}

exit(0);
