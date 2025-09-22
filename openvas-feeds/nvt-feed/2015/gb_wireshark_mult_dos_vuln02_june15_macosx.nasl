# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805395");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2015-3814", "CVE-2015-3812", "CVE-2015-3811");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-06-02 09:54:32 +0530 (Tue, 02 Jun 2015)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities-02 (Jun 2015) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The X11 dissector that is triggered when handling a specially crafted
  packet, which can result in a memory leak.

  - 'epan/dissectors/packet-wcp.c' in the WCP dissector improperly refers to
  previously processed bytes.

  - The IEEE 802.11 dissector that is triggered when handling a malformed
  packet, which can result in an infinite loop.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.10.x before 1.10.14
  and 1.12.x before 1.12.5 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 1.10.14 or 1.12.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-18.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74637");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74635");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74631");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"1.10.0", test_version2:"1.10.13")) {
  fix = "1.10.14";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"1.12.0", test_version2:"1.12.4")) {
  fix = "1.12.5";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
