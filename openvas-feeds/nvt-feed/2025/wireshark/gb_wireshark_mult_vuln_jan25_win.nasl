# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834912");
  script_version("2025-01-31T15:39:24+0000");
  script_cve_id("CVE-2024-0208", "CVE-2024-0209");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-10 14:03:18 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2025-01-07 14:15:11 +0530 (Tue, 07 Jan 2025)");
  script_name("Wireshark 3.6.x < 3.6.20, 4.0.x < 4.0.12, 4.2.0 Multiple Vulnerabilities (Jan 2025) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-0208: GVCP dissector crash

  - CVE-2024-0209: IEEE 1609.2 dissector crash");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause denial of service via packet injection or crafted capture file.");

  script_tag(name:"affected", value:"Wireshark version 4.2.0, 4.0.0 to 4.0.11,
  and 3.6.0 to 3.6.19 on Windows.");

  script_tag(name:"solution", value:"Update to version 4.2.1 or 4.0.12 or
  3.6.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-01.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-02.html");
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_equal(version:vers, test_version:"4.2.0")) {
  fix = "4.2.1";
}

if(version_in_range(version: vers, test_version: "4.0.0", test_version2: "4.0.11")) {
  fix = "4.0.12";
}

if(version_in_range(version: vers, test_version: "3.6.0", test_version2: "3.6.19")) {
  fix = "3.6.20";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
