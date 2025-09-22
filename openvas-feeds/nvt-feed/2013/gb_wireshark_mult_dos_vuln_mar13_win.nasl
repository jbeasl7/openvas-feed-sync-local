# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803330");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2013-2478", "CVE-2013-2480", "CVE-2013-2481", "CVE-2013-2482",
                "CVE-2013-2483", "CVE-2013-2484", "CVE-2013-2485", "CVE-2013-2488");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-03-11 18:57:44 +0530 (Mon, 11 Mar 2013)");
  script_name("Wireshark Multiple Dissector Multiple DoS Vulnerabilities (Mar 2013) - Windows");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58340");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58351");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58353");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58355");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58356");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58357");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58362");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58365");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028254");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause denial of
  service or to consume excessive CPU resources.");

  script_tag(name:"affected", value:"Wireshark 1.6.x before 1.6.14, 1.8.x before 1.8.6 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to errors in MS-MMS, RTPS, RTPS2, Mount, AMPQ, ACN,
  CIMD, FCSP and DTLS dissectors.");

  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.14 or 1.8.6 or later.");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

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

if(version=~ "^1\.[68]") {
  if(version_in_range(version:version, test_version:"1.6.0", test_version2:"1.6.13") ||
     version_in_range(version:version, test_version:"1.8.0", test_version2:"1.8.5")){
    security_message(port:0, data:"The target host was found to be vulnerable");
    exit(0);
  }
}
