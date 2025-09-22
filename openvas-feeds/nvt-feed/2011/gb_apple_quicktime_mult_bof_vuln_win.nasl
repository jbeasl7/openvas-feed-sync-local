# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802133");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2011-0245", "CVE-2011-0246", "CVE-2011-0247",
                "CVE-2011-0248", "CVE-2011-0249", "CVE-2011-0250",
                "CVE-2011-0251", "CVE-2011-0252", "CVE-2011-0256",
                "CVE-2011-0257", "CVE-2011-0258");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple QuickTime Multiple Buffer Overflow Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49396");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011//Aug/msg00000.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the currently logged-in user. Viewing a maliciously crafted
  movie file may lead to an unexpected application termination.");

  script_tag(name:"affected", value:"Apple QuickTime version prior to 7.7.");

  script_tag(name:"insight", value:"The flaws are due to

  - a buffer overflow error, when handling pict files.

  - heap buffer overflow error, when handling 'GIF' images and 'STSC', 'STSS',
    'STSZ' and 'STTS' atoms in QuickTime movie files.

  - multiple stack buffer overflows existed in the handling of 'H.264' encoded
    movie files.

  - stack buffer overflow existed in the QuickTime ActiveX control's handling
    of 'QTL' files.

  - an integer overflow existed in the handling of track run atoms in
    QuickTime movie files.

  - improper bounds checking when handling 'mp4v' codec information.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.7 or later.");

  script_tag(name:"summary", value:"Apple QuickTime is prone to multiple buffer overflow vulnerabilities.");

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

if(version_is_less(version:vers, test_version:"7.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.7", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
