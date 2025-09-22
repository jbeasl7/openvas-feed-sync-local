# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800247");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0599", "CVE-2009-0600", "CVE-2009-0601");
  script_name("Wireshark Multiple Vulnerabilities (Feb 2009) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33872");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33690");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-01.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/attachment.cgi?id=2590");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause denial of service to the
  application by crafting malicious packets.");
  script_tag(name:"affected", value:"Wireshark for Windows version 1.0.5 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - a boundary error in the processing of NetScreen Snoop capture files.

  - format string vulnerability in wireshark through format string specifiers
    in the HOME environment variable.

  - improper handling of Tektronix K12 text capture files as demonstrated by a
    file with exactly one frame.");
  script_tag(name:"solution", value:"Upgrade to the latest version 1.0.6.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"0.99.6", test_version2:"1.0.5")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"0.99.6 - 1.0.5", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
