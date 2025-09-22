# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800578");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0951", "CVE-2009-0952", "CVE-2009-0953",
                "CVE-2009-0954", "CVE-2009-0955", "CVE-2009-0956",
                "CVE-2009-0957", "CVE-2009-0185", "CVE-2009-0188");
  script_name("Apple QuickTime Multiple Vulnerabilities (Jun 2009)");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"affected", value:"Apple QuickTime version prior to 7.6.2 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to

  - an unspecified error while handling malicious 1)FLC compression files,
    2)compressed PSD images, 3)PICT images, 4)JP2 images.

  - an error in the parsing of Sorenson Video 3 content.

  - a boundary error in the processing of MS ADPCM encoded audio data.

  - an error due to the usage of uninitialised memory when a movie with a
    user data atom size of zero is viewed.

  - a sign extension error while the handling malicious image description
    atoms in an Apple video file.");

  script_tag(name:"summary", value:"Apple QuickTime is prone to Multiple Vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.6.2 or later.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code,
  cause memory corruption or unexpected application termination via specially
  crafted files, images and videos.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35159");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35161");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35163");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35165");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35166");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35167");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35168");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Jun/msg00000.html");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.6.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.6.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
