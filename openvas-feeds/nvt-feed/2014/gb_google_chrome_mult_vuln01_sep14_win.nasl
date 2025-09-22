# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804763");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-3177", "CVE-2014-3176", "CVE-2014-3175", "CVE-2014-3174",
                "CVE-2014-3173", "CVE-2014-3172", "CVE-2014-3171", "CVE-2014-3170",
                "CVE-2014-3169", "CVE-2014-3168");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-09-11 11:23:16 +0530 (Thu, 11 Sep 2014)");

  script_name("Google Chrome Multiple Vulnerabilities - 01 (Sep 2014) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Some errors within V8, IPC, sync, and extensions.

  - A use-after-free error exists within SVG.

  - A use-after-free error exists within DOM.

  - An error within Extension permission dialog.

  - A use-after-free error exists within bindings.

  - An error exists within extension debugging.

  - An uninitialized memory read error exists in WebGL.

  - An uninitialized memory read error exists in Web Audio.

  - and some unspecified errors exist.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to spoof certain content, bypass certain security restrictions, and compromise
  a user's system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 37.0.2062.94
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 37.0.2062.94
  or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69401");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69403");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69404");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69405");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69406");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69407");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030767");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2014/08/stable-channel-update_26.html");

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"37.0.2062.94"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"37.0.2062.94");
  security_message(port:0, data:report);
  exit(0);
}
