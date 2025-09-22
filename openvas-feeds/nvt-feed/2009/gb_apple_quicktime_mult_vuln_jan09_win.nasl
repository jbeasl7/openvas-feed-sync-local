# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900074");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0001", "CVE-2009-0002", "CVE-2009-0003", "CVE-2009-0004",
                "CVE-2009-0005", "CVE-2009-0006", "CVE-2009-0007", "CVE-2009-0008");
  script_name("Apple QuickTime Multiple Vulnerabilities (Jan 2009) - Windows");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Jan/msg00000.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33393");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Jan/msg00001.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Attackers can execute arbitrary code by sending maliciously crafted RTSP
  URLs and viewing a maliciously crafted QTVR file can lead to unexpected application termination.");

  script_tag(name:"affected", value:"Apple QuickTime before 7.60.92.0 on Windows (Any).");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.60.92.0 or later.");

  script_tag(name:"summary", value:"Apple QuickTime is prone to Multiple Vulnerabilities.");

  script_tag(name:"insight", value:"- Application fails in handling of RTSP URLs, THKD atoms in QTVR (QuickTime
  Virtual Reality) movie files and jpeg atoms in QT movie files.

  - Popping of overflow errors while processing an AVI movie file.

  - Player fails to handle MPEG-2 video files with MP3 audio content and
    H.263 encoded movie files.

  - Signedness flaw in handling of Cinepak encoded movie files.

  - Input validation flaw exists in the QT MPEG-2 Playback Component.");

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

if(version_is_less_equal(version:vers, test_version:"7.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
