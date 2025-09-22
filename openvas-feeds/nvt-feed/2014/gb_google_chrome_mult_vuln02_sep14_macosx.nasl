# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804482");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-3178", "CVE-2014-3179");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-09-16 15:30:13 +0530 (Tue, 16 Sep 2014)");

  script_name("Google Chrome Multiple Vulnerabilities - 02 (Sep 2014) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use-after-free error in rendering.

  - Various errors in internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass certain security restrictions, and compromise a user's system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 37.0.2062.120
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 37.0.2062.120
  or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60988");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69710");
  script_xref(name:"URL", value:"https://src.chromium.org/viewvc/blink?revision=180539&view=revision");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/09/stable-channel-update_9.html");
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(version_is_less(version:chromeVer, test_version:"37.0.2062.120"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"37.0.2062.120");
  security_message(port:0, data:report);
  exit(0);
}
