# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815782");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2020-9431", "CVE-2020-9430", "CVE-2020-9428");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-10 19:05:00 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-03-03 15:04:47 +0530 (Tue, 03 Mar 2020)");
  script_name("Wireshark Security Updates (wnpa-sec-2020-03, wnpa-sec-2020-04, wnpa-sec-2020-05) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to

  - An uncontrolled resource consumption issue in LTE RRC dissector.

  - An improper input validation issue in WiMax DLMAP dissector.

  - An improper neutralization issue in  EAP dissector.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to crash Wireshark by injecting a malformed packet onto the wire or by
  convincing someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.6.0 to 2.6.14,
  3.0.0 to 3.0.8, and 3.2.0 to 3.2.1.");

  script_tag(name:"solution", value:"Update to version 2.6.15, 3.0.9, 3.2.2 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2020-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2020-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2020-05.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_in_range(version:version, test_version:"2.6.0", test_version2:"2.6.14")) {
  fix = "2.6.15";
}

else if(version_in_range(version:version, test_version:"3.0.0", test_version2:"3.0.8")) {
  fix = "3.0.9";
}

else if(version_in_range(version:version, test_version:"3.2.0", test_version2:"3.2.1")) {
  fix = "3.2.2";
}

if(fix){
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
