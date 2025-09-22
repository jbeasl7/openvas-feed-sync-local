# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834768");
  script_version("2025-07-18T15:43:33+0000");
  script_cve_id("CVE-2024-11595", "CVE-2024-11596");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-07 16:52:28 +0000 (Wed, 07 May 2025)");
  script_tag(name:"creation_date", value:"2024-11-21 10:47:37 +0530 (Thu, 21 Nov 2024)");
  script_name("Wireshark Security Update (wnpa-sec-2024-14) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-11595: FiveCo RAP dissector infinite loop

  - CVE-2024-11596: dissector crash");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service attacks.");

  script_tag(name:"affected", value:"Wireshark version 4.4.0 through 4.4.1 and
  4.2.0 through 4.2.8 on Windows.");

  script_tag(name:"solution", value:"Update to version 4.4.2 or 4.2.9 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-14.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-15.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version: vers, test_version: "4.4.0", test_version2: "4.4.1")) {
  fix = "4.4.2";
}
else if(version_in_range(version: vers, test_version: "4.2.0", test_version2: "4.2.8")) {
  fix = "4.2.9";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
