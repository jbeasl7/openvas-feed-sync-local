# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805377");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-1250", "CVE-2015-1243");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-05-04 14:23:48 +0530 (Mon, 04 May 2015)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (May 2015) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A Use-after-free flaw in the MutationObserver::disconnect function
    in core/dom/MutationObserver.cpp script in the DOM implementation in Blink.

  - Multiple Unspecified flaws due to unknown vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service condition and other unspecified impacts.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  42.0.2311.135 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  42.0.2311.135 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/04/stable-channel-update_28.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)) exit(0);

if(version_is_less(version:chromeVer, test_version:"42.0.2311.135"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     42.0.2311.135'  + '\n';
  security_message(data:report);
  exit(0);
}
