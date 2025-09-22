# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800290");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0304");
  script_name("Wireshark Multiple Buffer Overflow Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37985");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0239");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_family("Buffer overflow");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash an affected application or
  potentially execute arbitrary code.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.5 and 0.9.15 to 1.0.10");
  script_tag(name:"insight", value:"The flaws are caused by buffer overflow errors in the LWRES dissector when
  processing malformed data or packets.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.6 or 1.0.11");
  script_tag(name:"summary", value:"Wireshark is prone to multiple Buffer Overflow vulnerabilities.");
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

if(version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.5") ||
   version_in_range(version:version, test_version:"0.9.15", test_version2:"1.0.10")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
