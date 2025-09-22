# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803902");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-2867", "CVE-2013-2879", "CVE-2013-2868", "CVE-2013-2869", "CVE-2013-2870",
                "CVE-2013-2853", "CVE-2013-2871", "CVE-2013-2873", "CVE-2013-2875", "CVE-2013-2876",
                "CVE-2013-2877", "CVE-2013-2878", "CVE-2013-2880",
                "CVE-2013-2874"); # nb: Windows only
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-07-16 18:40:12 +0530 (Tue, 16 Jul 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Jul 2013) - Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  bypass security restrictions, disclose potentially sensitive data, or cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 28.0.1500.71 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - Error exists when setting up sign-in and sync operations.

  - An out-of-bounds read error exists within text handling.

  - 'parser.c in libxml2' has out-of-bounds read error, related to the lack of
  checks for the XML_PARSER_EOF state.

  - 'browser/extensions/api/tabs/tabs_api.cc' does not enforce restrictions on
  the capture of screenshots by extensions.

  - An out-of-bounds read error exists in SVG handling.

  - Unspecified error related to GL textures, only when an Nvidia GPU is used.

  - Unspecified use-after-free vulnerabilities.

  - An out-of-bounds read error exists within JPEG2000 handling.

  - Unspecified error exists within sync of NPAPI extension component.

  - Does not properly prevent pop.

  - HTTPS implementation does not ensure how headers are terminated.");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 28.0.1500.71 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54017");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61046");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61058");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61060");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61061");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/07/stable-channel-update.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"28.0.1500.71"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"28.0.1500.71");
  security_message(port: 0, data: report);
  exit(0);
}
