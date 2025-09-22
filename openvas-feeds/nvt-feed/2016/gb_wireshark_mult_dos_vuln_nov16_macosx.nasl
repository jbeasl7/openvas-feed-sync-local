# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809810");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2016-9374", "CVE-2016-9376", "CVE-2016-9373", "CVE-2016-9375");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-18 12:48:56 +0530 (Fri, 18 Nov 2016)");
  script_name("Wireshark Multiple DoS Vulnerabilities (Nov 2016) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The AllJoyn dissector could crash with a buffer over-read, triggered by
    network traffic or a capture file.

  - The DCERPC dissector could crash with a use-after-free, triggered by network
    traffic or a capture file.

  - The DTN dissector could go into an infinite loop, triggered by network
    traffic or a capture file.

  - The OpenFlow dissector could crash with memory exhaustion, triggered by network
    traffic or a capture file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 to 2.2.1 and
  2.0.0 to 2.0.7 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 2.0.8, 2.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-59.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94369");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-60.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-61.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-62.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"2.0", test_version2:"2.0.7")) {
  fix = "2.0.8";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"2.2.0", test_version2:"2.2.1")) {
  fix = "2.2.2";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
