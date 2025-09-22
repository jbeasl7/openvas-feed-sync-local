# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802795");
  script_version("2024-02-27T14:36:53+0000");
  script_cve_id("CVE-2012-0663", "CVE-2012-0665", "CVE-2011-3458", "CVE-2011-3459",
                "CVE-2012-0658", "CVE-2012-0659", "CVE-2012-0666", "CVE-2011-3460",
                "CVE-2012-0667", "CVE-2012-0661", "CVE-2012-0668", "CVE-2012-0669",
                "CVE-2012-0670", "CVE-2012-0671", "CVE-2012-0265", "CVE-2012-0664",
                "CVE-2012-0660");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-05-18 13:04:18 +0530 (Fri, 18 May 2012)");
  script_name("Apple QuickTime Multiple Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5261");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51809");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51814");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53467");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53571");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53574");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53577");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53583");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53584");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47447/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027065");
  script_xref(name:"URL", value:"http://prod.lists.apple.com/archives/security-announce/2012/May/msg00005.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code or
  cause a denial of service.");

  script_tag(name:"affected", value:"QuickTime Player version prior to 7.7.2 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to

  - Errors within the handling of TeXML files.

  - An error when handling of text tracks and MPEG files and sean atoms.

  - An error while handling RLE, JPEG2000, H.264 and Sorenson encoded
    movie files.

  - An error exists within the parsing of MP4 encoded files and .pict files.

  - An off-by-one error can be exploited to cause a single byte buffer overflow.

  - An error when handling audio samples.

  - An error within the plugin's handling of QTMovie objects.

  - An error when parsing the MediaVideo header in videos encoded with the PNG
    format.

  - A signedness error within the handling of QTVR movie files.

  - A boundary error in QuickTime.qts when extending a file path based on its
    short path.");

  script_tag(name:"solution", value:"Upgrade to QuickTime Player version 7.7.2 or later.");

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

if(version_is_less(version:vers, test_version:"7.7.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.7.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
