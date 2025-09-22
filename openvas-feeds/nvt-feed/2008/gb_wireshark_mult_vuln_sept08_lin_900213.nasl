# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900213");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Wireshark Multiple Vulnerabilities (Sep 2008) - Linux");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31674");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31009");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2493");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2008-05.html");

  script_tag(name:"summary", value:"Check for vulnerable version of Wireshark.");

  script_tag(name:"affected", value:"Wireshark versions 1.0.2 and prior on Linux (All).");

  script_tag(name:"solution", value:"Update to version 1.0.3 or later.");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service
  condition or application crash by injecting a series of malformed
  packets or by convincing the victim to read a malformed packet.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit( 0 );

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"1.0.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.0.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
