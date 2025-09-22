# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800074");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-12-04 14:15:00 +0100 (Thu, 04 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5285");
  script_name("Wireshark SMTP Processing DoS Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32422");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");

  script_tag(name:"impact", value:"Successful attacks may cause the application to crash via specially
  crafted packets.");

  script_tag(name:"affected", value:"Wireshark version 1.0.4 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error in the SMTP dissector while processing
  large SMTP packets.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.5.");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

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

if(version_is_less_equal(version:version, test_version:"1.0.4")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Less than or equal to 1.0.4", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
