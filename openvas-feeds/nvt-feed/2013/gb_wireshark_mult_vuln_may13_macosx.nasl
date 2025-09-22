# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803621");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2013-3562", "CVE-2013-3561", "CVE-2013-3560", "CVE-2013-3559",
                "CVE-2013-3558", "CVE-2013-3555");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-05-28 15:42:11 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark Multiple Dissector Multiple Vulnerabilities (May 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59992");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59994");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59995");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59996");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59998");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60002");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60003");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.7.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash the
  application, resulting in denial of service condition.");
  script_tag(name:"affected", value:"Wireshark versions 1.8.x before 1.8.7 on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws are due to errors in Websocket, MySQL, ETCH, MPEG DSM-CC,
  DCP ETSI, PPP CCP and GTPv2 dissectors.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.8.7 or later.");
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
  if(version_in_range(version:version, test_version:"1.8.0", test_version2:"1.8.6")){
    security_message(port:0, data:"The target host was found to be vulnerable");
    exit(0);
  }
}

exit(99);
