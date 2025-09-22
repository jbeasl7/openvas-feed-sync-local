# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806763");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767",
                "CVE-2015-6768", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772",
                "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776",
                "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780",
                "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6784", "CVE-2015-6785",
                "CVE-2015-6786", "CVE-2015-6787", "CVE-2015-8478", "CVE-2015-8479",
                "CVE-2015-8480", "CVE-2015-6769");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:22:00 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-12-07 16:08:15 +0530 (Mon, 07 Dec 2015)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Dec 2015) - Mac OS X");

  script_tag(name:"summary", value:"google chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - 'VideoFramePool::PoolImpl::CreateFrame' function in
    'media/base/video_frame_pool.cc' script does not initialize memory for a
    video-frame data structure.

  - Multiple unspecified vulnerabilities.

  - Multiple cross-origin bypass vulnerabilities.

  - Multiple out of bounds access vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - Integer overflow in Sfntly.

  - Content spoofing vulnerability in Omnibox.

  - Escaping issue in saved pages.

  - Wildcard matching issue in CSP.

  - Multiple scheme bypass vulnerabilities.

  - Type confusion vulnerability in PDFium.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to execute arbitrary code or to cause a denial of service or possibly have
  other impact, bypass the security restrictions and gain access to potentially
  sensitive information.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  47.0.2526.73 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  47.0.2526.73 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/12/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78416");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"47.0.2526.73"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     47.0.2526.73'  + '\n';
  security_message(data:report);
  exit(0);
}
