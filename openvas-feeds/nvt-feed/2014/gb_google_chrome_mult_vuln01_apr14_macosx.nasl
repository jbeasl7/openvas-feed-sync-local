# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804549");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-1716", "CVE-2014-1717", "CVE-2014-1718", "CVE-2014-1719",
                "CVE-2014-1720", "CVE-2014-1721", "CVE-2014-1722", "CVE-2014-1723",
                "CVE-2014-1724", "CVE-2014-1725", "CVE-2014-1726", "CVE-2014-1727",
                "CVE-2014-1728", "CVE-2014-1729");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-22 13:36:13 +0530 (Tue, 22 Apr 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 (Apr 2014) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A use-after-free error exists within 'web workers', 'DOM', 'forms' and 'speech'.

  - An unspecified error exists when handling URLs containing 'RTL' characters.

  - An integer overflow error exists within 'compositor'.

  - An error when handling certain 'window property'.

  - An unspecified error within 'V8'.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct cross-site
scripting attacks, bypass certain security restrictions, and compromise
a user's system.");
  script_tag(name:"affected", value:"Google Chrome version prior to 34.0.1847.116 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 34.0.1847.116 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57506");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66704");
  script_xref(name:"URL", value:"http://threatpost.com/google-patches-31-flaws-in-chrome/105326");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/04/stable-channel-update.html");
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

if(version_is_less(version:chromeVer, test_version:"34.0.1847.116"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"34.0.1847.116");
  security_message(port:0, data:report);
  exit(0);
}
