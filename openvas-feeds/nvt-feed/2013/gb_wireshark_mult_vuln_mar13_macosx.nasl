# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803333");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-2479", "CVE-2013-2477",
                "CVE-2013-2476", "CVE-2013-2475");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:11 +0530 (Mon, 11 Mar 2013)");
  script_name("Wireshark Multiple Dissector Multiple Vulnerabilities (Mar 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58349");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58350");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58363");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58364");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028254");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause denial of
  service or to consume excessive CPU resources.");

  script_tag(name:"affected", value:"Wireshark versions 1.8.x before 1.8.6 on Mac OS X.");

  script_tag(name:"insight", value:"Multiple flaws are due to errors in RELOAD, MPLS Echo, CSN.1, HART/IP and TCP
  dissectors.");

  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.8.6 or later.");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version=~ "^1\.8") {
  if(version_in_range(version:version, test_version:"1.8.0", test_version2:"1.8.5")) {
    security_message(port:0, data:"The target host was found to be vulnerable");
    exit(0);
  }
}

exit(99);
