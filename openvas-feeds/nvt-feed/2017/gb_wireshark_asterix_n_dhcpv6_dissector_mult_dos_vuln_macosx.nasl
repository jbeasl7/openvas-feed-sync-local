# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810528");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2017-5596", "CVE-2017-5597");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-01-30 15:13:00 +0530 (Mon, 30 Jan 2017)");
  script_name("Wireshark ASTERIX And DHCPv6 Dissector Multiple DoS Vulnerabilities - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An integer overflow error in the 'epan/dissectors/packet-asterix.c' script.

  - An integer overflow error in the 'epan/dissectors/packet-dhcpv6.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to enter an infinite loop and consume
  excessive CPU resources, resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 to 2.2.3 and
  2.0.0 to 2.0.9 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 2.2.4 or
  2.0.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-01.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95795");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95798");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-02.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13344");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"2.2.0", test_version2:"2.2.3")) {
  fix = "2.2.4";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.0.9")) {
  fix = "2.0.10";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
