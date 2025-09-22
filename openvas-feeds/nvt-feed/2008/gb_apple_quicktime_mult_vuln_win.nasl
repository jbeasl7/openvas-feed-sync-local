# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800102");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-1581", "CVE-2008-1582", "CVE-2008-1583",
                "CVE-2008-1584", "CVE-2008-1585");
  script_xref(name:"CB-A", value:"08-0094");
  script_name("Apple QuickTime Multiple Arbitrary Code Execution Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"affected", value:"Apple QuickTime before 7.5 on Windows (Any).");

  script_tag(name:"insight", value:"The flaws are due to:

  - boundary error when parsing packed scanlines from a PixData
    structure in a PICT file which can be exploited via specially crafted
    PICT file.

  - memory corruption issue in AAC-encoded media content can be
    exploited via a specially crafted media file.

  - error in the handling of PICT files or Indeo video codec content that
    can be exploited via a specially crafted PICT file or movie file with
    Indeo video codec content respectively.

  - error in the handling of file URLs that can be exploited by making user
    to play maliciously crafted QuickTime content.");

  script_tag(name:"summary", value:"Apple QuickTime is prone to Multiple Arbitrary Code Execution Vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.5 or later.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary
  code or unexpected application termination.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1991");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29619");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29293");
  script_xref(name:"URL", value:"http://www.nruns.com/security_advisory_quicktime_arbitrary_code_execution.php");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
