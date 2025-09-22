# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814134");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-18225", "CVE-2018-18226");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-20 01:15:00 +0000 (Fri, 20 Mar 2020)");
  script_tag(name:"creation_date", value:"2018-10-15 12:30:47 +0530 (Mon, 15 Oct 2018)");
  script_name("Wireshark Steam IHS Discovery/CoAP Dissector DoS Vulnerabilities - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaws are due to insufficient validation
  of user-supplied input processed by Steam In-Home Streaming (IHS) Discovery
  and Constrained Application Protocol (CoAP) dissector components.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service (DoS) condition on a targeted system.");

  script_tag(name:"affected", value:"Wireshark version 2.6.0 to 2.6.3 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 2.6.4 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-48.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-49.html");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=59009");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=59008");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"2.6.0", test_version2:"2.6.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.6.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
