# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903023");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-1591");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-04-25 18:34:41 +0530 (Wed, 25 Apr 2012)");
  script_name("Wireshark DECT Buffer Overflow Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47392");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66834");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1022");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-06.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause buffer overflow and
  execute arbitrary code on the system.");
  script_tag(name:"affected", value:"Wireshark version 1.4.0 through 1.4.4");
  script_tag(name:"insight", value:"The flaw is due to error in the 'DECT' dissector when processing
  malformed data, which could allow code execution via malformed packets or
  a malicious PCAP file.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.5 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a buffer overflow vulnerability.");
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

if(version_in_range(version:version, test_version:"1.4.0", test_version2:"1.4.4")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"1.4.0 - 1.4.4", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
