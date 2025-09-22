# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812633");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2018-5335", "CVE-2018-5334", "CVE-2018-5336");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-12 16:00:00 +0000 (Tue, 12 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-01-16 13:14:57 +0530 (Tue, 16 Jan 2018)");
  script_name("Wireshark Security Updates (wnpa-sec-2018-04_wnpa-sec-2018-03_wnpa-sec-2018-01) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The WCP dissector could crash.

  - The IxVeriWave file parser could crash.

  - The JSON, XML, NTP, XMPP, and GDB dissectors could crash.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to make wireshark crash.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0 to 2.4.3, 2.2.0 to
  2.2.11 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.4 or 2.2.12
  or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-04");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-03");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-01");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.3")) {
  fix = "2.4.4";
}

else if(version_in_range(version:vers, test_version:"2.2.0", test_version2:"2.2.11")) {
  fix = "2.2.12";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
