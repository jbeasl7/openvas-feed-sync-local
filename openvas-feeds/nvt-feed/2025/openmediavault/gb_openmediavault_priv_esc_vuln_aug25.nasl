# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openmediavault:openmediavault";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155204");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-25 03:12:45 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-50674");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Openmediavault <= 7.4.17 Privilege Escalation Vulnerability.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_openmediavault_ssh_detect.nasl");
  script_mandatory_keys("openmediavault/detected");

  script_tag(name:"summary", value:"Openmediavault is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The changePassword method in file
  /usr/share/php/openmediavault/system/user.inc allows local authenticated attackers to escalate
  privileges to root.");

  script_tag(name:"affected", value:"Openmediavault version 7.4.17 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 25th August, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://gist.github.com/xbz0n/4b98e9291ddd5bb5e6232609e36b2082");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "7.4.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
