# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901017");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2202", "CVE-2009-2203", "CVE-2009-2798", "CVE-2009-2799");
  script_name("Apple QuickTime Multiple Vulnerabilities (Sep 2009)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36328");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00002.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in the
  context of an affected application, and can cause Denial of Service.");

  script_tag(name:"affected", value:"Apple QuickTime before 7.6.4 on Windows.");

  script_tag(name:"insight", value:"- A memory corruption issue exists when handling 'H.264' movie files.

  - An error in the parsing of 'MPEG-4' video files which causes buffer
    overflow.

  - An integer overflow error when processing the 'SectorShift' and 'cSectFat'
    fields of a FlashPix file header. This can be exploited to cause a
    heap-based buffer overflow via a specially crafted FlashPix '.fpx' file.

  - A boundary error exists when processing samples from a 'H.264' encoded MOV
    file. This can be exploited to cause a heap-based buffer overflow via a
    specially crafted 'MOV' file.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.6.4 or later.");

  script_tag(name:"summary", value:"Apple QuickTime is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.6.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.6.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
