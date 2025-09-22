# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802763");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2012-1596", "CVE-2012-1595", "CVE-2012-1593");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-04-24 15:17:23 +0530 (Tue, 24 Apr 2012)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.12 and 1.6.x before 1.6.6 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - A NULL pointer dereference error in the ANSI A dissector can be exploited
    to cause a crash via a specially crafted packet.

  - An error in the MP2T dissector when allocating memory can be exploited to
    cause a crash via a specially crafted packet.

  - An error exists in the pcap and pcap-ng file parsers when reading ERF data
    and can cause a crash via a specially crafted trace file.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.12, 1.6.6 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-07.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52735");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52736");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52737");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-06.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-04.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/03/28/13");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc?view=revision&revision=41001");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range (version:version, test_version:"1.4.0", test_version2:"1.4.11") ||
   version_in_range (version:version, test_version:"1.6.0", test_version2:"1.6.5")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
