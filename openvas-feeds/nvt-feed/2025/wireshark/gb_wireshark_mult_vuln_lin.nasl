# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836390");
  script_version("2025-06-02T05:40:56+0000");
  script_cve_id("CVE-2023-2854", "CVE-2023-0666");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-06-02 05:40:56 +0000 (Mon, 02 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 13:29:37 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"creation_date", value:"2025-05-29 22:38:19 +0530 (Thu, 29 May 2025)");
  script_name("Wireshark Multiple Vulnerabilities (May 2025) - Linux");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution and conduct denial of service via packet crafted
  capture file.");

  script_tag(name:"affected", value:"Wireshark version 4.0.0 through 4.0.5 on
  Linux.");

  script_tag(name:"solution", value:"Update to version 4.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-17.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-18.html");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

if(version_in_range(version: vers, test_version: "4.0.0", test_version2: "4.0.5")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "4.0.6", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);