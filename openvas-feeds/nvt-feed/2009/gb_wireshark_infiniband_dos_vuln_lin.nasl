# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900593");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2563");
  script_name("Wireshark Infiniband Dissector Denial of Service Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35748");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1970");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-04.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service condition.");

  script_tag(name:"affected", value:"Wireshark version 1.0.6 through 1.2.0 on Linux.");

  script_tag(name:"insight", value:"An unspecified error in the infiniband dissector which can be exploited when
  running on unspecified platforms via unknown vectors.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.1 or later.");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.0.6", test_version2:"1.2.0")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range: "1.0.6 - 1.2.0", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
