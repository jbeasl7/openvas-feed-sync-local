# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900121");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_cve_id("CVE-2008-3615", "CVE-2008-3635", "CVE-2008-3624", "CVE-2008-3625",
                "CVE-2008-3614", "CVE-2008-3626", "CVE-2008-3627", "CVE-2008-3628",
                "CVE-2008-3629");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Apple QuickTime Movie/PICT/QTVR Multiple Remote Vulnerabilities (HT3027)");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496161");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496163");
  script_xref(name:"URL", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=744");

  script_tag(name:"summary", value:"Apple QuickTime is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The flaws exist due to:

  - an uninitialized memory access inn the Indeo v5 codec and lack of
  proper bounds checking within QuickTimeInternetExtras.qtx file.

  - improper handling of panorama atoms in QTVR movie files.

  - improper handling of maxTilt, minFieldOfView and maxFieldOfView
  parameters in panorama track PDAT atoms.

  - an uninitialized memory access in the third-party Indeo v5 codec.

  - an invalid pointer in handling of PICT images.

  - memory corruption in handling of STSZ atoms in movie files within
  CallComponentFunctionWithStorage() function.

  - multiple memory corruption in H.264 encoded movie files.

  - parsing of movie video files in QuickTimeH264.scalar and MP4 video
  files in QuickTimeH264.qtx.");

  script_tag(name:"affected", value:"Apple QuickTime versions prior to 7.5.5 on Windows (all).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 7.5.5.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain
  unauthorized access to execute arbitrary code and trigger a denial of service condition.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.5.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.5.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
