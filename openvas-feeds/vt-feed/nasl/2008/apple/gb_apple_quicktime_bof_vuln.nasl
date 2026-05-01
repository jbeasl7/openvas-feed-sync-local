# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800319");
  script_version("2026-04-28T06:28:05+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:05 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5406");
  script_name("Apple QuickTime Malformed .mov File Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7296");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32540");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46984");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow the attacker execution of
  arbitrary codes in the context of the affected application and can perform denial of service.");

  script_tag(name:"affected", value:"Apple QuickTime version 7.5.5 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to a failure in handling long arguments on a
  .mov file.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 7.6.6 or later.");

  script_tag(name:"summary", value:"QuickTime is prone to a buffer overflow vulnerability.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.6.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.6.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
