# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803623");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2013-0912");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-05-28 17:20:48 +0530 (Tue, 28 May 2013)");
  script_name("Google Chrome Webkit Remote Code Execution Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52534");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58388");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/03/stable-channel-update_7.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attackers to execute arbitrary code via
  crafted SVG document.");
  script_tag(name:"affected", value:"Google Chrome version prior to 25.0.1364.160 on Mac OS X.");
  script_tag(name:"insight", value:"WebKit contains a type confusion flaw in the 'SVGViewSpec::viewTarget'
  function in WebCore/svg/SVGViewSpec.cpp when handling non-SVG elements.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 25.0.1364.160 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"25.0.1364.160"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"25.0.1364.160");
  security_message(port: 0, data: report);
  exit(0);
}
