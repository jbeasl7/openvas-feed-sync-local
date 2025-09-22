# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800494");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-0527", "CVE-2010-0529", "CVE-2010-0528", "CVE-2010-0536");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple QuickTime Multiple Denial Of Service Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/392440.php");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023790.html");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010//Mar/msg00002.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attacker to cause an unexpected application
  termination or arbitrary code execution.");

  script_tag(name:"affected", value:"Apple QuickTime before 7.6.6 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An heap buffer overflow in the handling of PICT images.

  - A memory corruption issue in the handling of BMP images.

  - An integer overflow in the handling of 'PICT' images.

  - A memory corruption the handling of color tables in movie files.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.6.6 or later.");

  script_tag(name:"summary", value:"Apple QuickTime is prone to multiple Denial Of Service vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
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
