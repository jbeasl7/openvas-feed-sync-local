# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902199");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2287");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Wireshark SigComp Universal Decompressor Virtual Machine dissector BOF Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40112");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1418");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2010-05.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2010-06.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/06/11/1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"It has unknown impact and remote attack vectors.");
  script_tag(name:"affected", value:"Wireshark version 0.10.8 to 1.0.13 and 1.2.0 to 1.2.8");
  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error in the SigComp Universal
  Decompressor Virtual Machine dissector.");
  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.0.14 or 1.2.9:");
  script_tag(name:"summary", value:"Wireshark is prone to a buffer overflow vulnerability.");
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

if(version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.8") ||
   version_in_range(version:version, test_version:"0.10.8", test_version2:"1.0.13")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
