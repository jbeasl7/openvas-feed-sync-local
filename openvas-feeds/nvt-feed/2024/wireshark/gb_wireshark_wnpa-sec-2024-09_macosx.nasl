# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834209");
  script_version("2025-08-08T05:44:56+0000");
  script_cve_id("CVE-2024-4855");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-07 17:17:07 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-06-26 14:13:14 +0530 (Wed, 26 Jun 2024)");
  script_name("Wireshark Security Update (wnpa-sec-2024-09) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to an use after free
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an use after free
  issue in editcap.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause denial of service.");

  script_tag(name:"affected", value:"Wireshark version 3.6.0 through 3.6.23,
  4.0.0 through 4.0.14 and 4.2.0 through 4.2.4 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 3.6.24, 4.0.15 or 4.2.5
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-09.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range( version:version, test_version:"3.6.0", test_version2:"3.6.23")) {
  fix = "3.6.24";
}

if(version_in_range(version:version, test_version:"4.0.0", test_version2:"4.0.14")) {
  fix = "4.0.15";
}

if(version_in_range(version:version, test_version:"4.2.0", test_version2:"4.2.4")) {
  fix = "4.2.5";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
