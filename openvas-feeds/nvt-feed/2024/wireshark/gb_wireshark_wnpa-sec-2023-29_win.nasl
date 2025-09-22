# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834205");
  script_version("2025-04-17T05:39:39+0000");
  script_cve_id("CVE-2023-6175");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-17 05:39:39 +0000 (Thu, 17 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-16 18:53:23 +0000 (Wed, 16 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-06-26 12:43:02 +0530 (Wed, 26 Jun 2024)");
  script_name("Wireshark Security Update (wnpa-sec-2023-29) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to NetScreen file
  parser crash in Wireshark.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause denial of service.");

  script_tag(name:"affected", value:"Wireshark version 3.6.0 through 3.6.18,
  4.0.0 through 4.0.10 on Windows.");

  script_tag(name:"solution", value:"Update to version 4.0.11 or 3.6.19 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-29.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"4.0.0", test_version2:"4.0.10")) {
  fix = "4.0.11";
}

if(version_in_range(version:version, test_version:"3.6.0", test_version2:"3.6.18")) {
  fix = "3.6.19";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
