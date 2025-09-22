# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836559");
  script_version("2025-08-01T05:45:36+0000");
  script_cve_id("CVE-2023-0417", "CVE-2023-0413", "CVE-2023-0416", "CVE-2023-0415",
                "CVE-2023-0411", "CVE-2023-0412");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 18:50:45 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"creation_date", value:"2025-07-31 12:16:56 +0530 (Thu, 31 Jul 2025)");
  script_name("Wireshark 3.6.x < 3.6.10, 4.0.x < 4.0.3 Multiple Vulnerabilities (Jul 2025) - Linux");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause denial of service via packet injection or crafted capture file.");

  script_tag(name:"affected", value:"Wireshark version 4.0.0 to 4.0.2 and
  3.6.0 to 3.6.10 on Linux.");

  script_tag(name:"solution", value:"Update to version 4.0.3 or 3.6.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-02.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-05.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-06.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-07.html");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version: vers, test_version: "4.0.0", test_version2: "4.0.2")) {
  fix = "4.0.3";
}

if(version_in_range(version: vers, test_version: "3.6.0", test_version2: "3.6.10")) {
  fix = "3.6.11";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
