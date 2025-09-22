# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802978");
  script_version("2024-07-23T05:05:30+0000");
  script_cve_id("CVE-2012-5237", "CVE-2012-5238", "CVE-2012-5240");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-10-08 14:20:21 +0530 (Mon, 08 Oct 2012)");
  script_name("Wireshark LDP PPP and HSRP dissector Multiple Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50843/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55754");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-27.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-26.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-29.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7668");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7581");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application, to crash the affected application,
  or to consume excessive CPU resources.");
  script_tag(name:"affected", value:"Wireshark versions 1.8.x prior to 1.8.3 on windows");
  script_tag(name:"insight", value:"Errors in the HSRP, PPP and LDP dissectors when processing certain
  packets can be exploited to cause an infinite loop and consume CPU
  resources or a buffer overflow.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.8.3 or later.");
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

if(version_in_range(version:version, test_version:"1.8.0", test_version2:"1.8.2")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"1.8.0 - 1.8.2", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
