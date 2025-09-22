# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107485");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-29 14:44:33 +0100 (Tue, 29 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Oracle Application Testing Suite Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Oracle Application Testing Suite.");

  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/oem/app-test/etest-101273.html");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

key_list = make_list("SYSTEM\CurrentControlSet\Services\");
if(isnull(key_list))
  exit(0);

foreach key(key_list) {
  foreach item(registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if(!appName || appName !~ "Oracle ATS Agent")
      continue;

    version = "unknown";
    concluded = appName;
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"ImagePath");
    if(loc) {
      split = split(loc, sep:"\");
      max = max_index(split) - 1;
      string = split[max - 2] + "\" + split[max - 1] + "\" + split[max];
      location = ereg_replace(string:loc, pattern:string, replace:'');

      path = location + "\\config\\version.properties";

      version_info = smb_read_file(fullpath:path, offset:0, count:3000);
      if(version_info) {
        versq = eregmatch(pattern:"oracle.version.build=([0-9.]+)", string:version_info);
        if(versq) {
          version = versq[1];
          concluded = appName + " " + versq[0];
        }
      }
    }

    set_kb_item(name:"oracle/application_testing_suite/win/detected", value:TRUE);

    register_and_report_cpe(app:"Oracle Application Testing Suite", ver:version, concluded:concluded,
                            base:"cpe:/a:oracle:application_testing_suite:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
    exit(0);
  }
}

exit(0);
