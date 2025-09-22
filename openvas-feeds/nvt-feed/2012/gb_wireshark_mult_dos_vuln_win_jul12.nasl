# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802907");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2012-2392", "CVE-2012-2393", "CVE-2012-3825", "CVE-2012-3826");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-07-05 13:52:34 +0530 (Thu, 05 Jul 2012)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities (Jul 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49226/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53651");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53652");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-08.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-09.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7138");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.13 and 1.6.x before 1.6.8 on Windows");
  script_tag(name:"insight", value:"- Errors in the ANSI MAP, ASF, BACapp, Bluetooth HCI, IEEE 802.11,
    IEEE 802.3, LTP, and R3 dissectors can be exploited to cause infinite loops
    via specially crafted packets.

  - An error in the DIAMETER dissector does not properly allocate memory and
    can be exploited to cause a crash via a specially crafted packet.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.13, 1.6.8 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range (version:version, test_version:"1.4.0", test_version2:"1.4.12") ||
   version_in_range (version:version, test_version:"1.6.0", test_version2:"1.6.7")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
