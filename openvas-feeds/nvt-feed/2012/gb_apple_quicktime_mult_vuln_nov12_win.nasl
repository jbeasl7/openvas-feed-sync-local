# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803047");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2011-1374", "CVE-2012-3757", "CVE-2012-3751", "CVE-2012-3758",
                "CVE-2012-3752", "CVE-2012-3753", "CVE-2012-3754", "CVE-2012-3755",
                "CVE-2012-3756");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-11-09 13:08:03 +0530 (Fri, 09 Nov 2012)");
  script_name("Apple QuickTime Multiple Vulnerabilities (Nov 2012) - Windows");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56438");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51226");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Nov/msg00002.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  cause a buffer overflow condition.");

  script_tag(name:"affected", value:"QuickTime Player version prior to 7.7.3 on Windows.");

  script_tag(name:"insight", value:"- Multiple boundary errors exist when handling a PICT file, a Targa file,
  the transform attribute of 'text3GTrack' elements and the 'rnet' box within MP4 file.

  - Use-after-free errors exist when handling '_qtactivex_' parameters within
  an HTML object and 'Clear()' method.");

  script_tag(name:"solution", value:"Upgrade to QuickTime Player version 7.7.3 or later.");

  script_tag(name:"summary", value:"Apple QuickTime is prone to multiple vulnerabilities.");

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

if(version_is_less(version:vers, test_version:"7.7.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.7.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
