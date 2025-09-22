# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803649");
  script_version("2024-02-21T05:06:27+0000");
  script_cve_id("CVE-2013-2865", "CVE-2013-2864", "CVE-2013-2863", "CVE-2013-2862",
                "CVE-2013-2861", "CVE-2013-2860", "CVE-2013-2859", "CVE-2013-2858",
                "CVE-2013-2857", "CVE-2013-2856", "CVE-2013-2855", "CVE-2013-2854");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-06-11 15:37:34 +0530 (Tue, 11 Jun 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Jun 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53681");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60395");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60396");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60399");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60401");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60403");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60404");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60405");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60406");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53681");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/06/stable-channel-update.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  bypass security restrictions, corrupt memory, or cause denial of service conditions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 27.0.1453.110 on Mac OS X.");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - Use-after-free errors in input handling, image handling, HTML5 Audio, SVG,
  and when accessing database APIs.

  - Unspecified errors with dev tools API, Skia GPU handling, SSL socket
  handling, and PDF viewer.");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 27.0.1453.110 or later.");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"27.0.1453.110"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"27.0.1453.110");
  security_message(port: 0, data: report);
  exit(0);
}
