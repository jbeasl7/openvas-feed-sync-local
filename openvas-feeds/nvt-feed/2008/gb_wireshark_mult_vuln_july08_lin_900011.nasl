# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900011");
  script_version("2025-03-05T05:38:52+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28485");
  script_cve_id("CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Wireshark Multiple Vulnerabilities (Jul 2008) - Linux");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");

  script_tag(name:"solution", value:"Upgrade to wireshark to 1.0.1 or later.

  Quick Fix : Disable the following dissectors, GSM SMS, PANA, KISMET, RTMPT, and RMI");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The flaws exist due to errors in GSM SMS dissector, PANA and KISMET
  dissectors, RTMPT dissector, RMI dissector, and in syslog dissector.");

  script_tag(name:"affected", value:"Wireshark versions prior to 1.0.1 on Linux (All).");

  script_tag(name:"impact", value:"Successful exploitation could result in application crash,
  disclose of system memory, and an incomplete syslog encapsulated packets.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit( 0 );

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"1.0.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.0.1", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
