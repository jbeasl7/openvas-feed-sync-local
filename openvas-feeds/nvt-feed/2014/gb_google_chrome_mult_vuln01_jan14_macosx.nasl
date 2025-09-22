# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804188");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-6641", "CVE-2013-6643", "CVE-2013-6644", "CVE-2013-6645",
                "CVE-2013-6646");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-01-21 11:29:43 +0530 (Tue, 21 Jan 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 - (Jan 2014) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A use-after-free error exists within web workers.

  - Use-after-free vulnerability in 'FormAssociatedElement::formRemovedFromTree'
 function in Blink.

  - Multiple unspecified errors.

  - Use-after-free vulnerability in 'OnWindowRemovingFromRootWindow' function.

  - An error in 'OneClickSigninBubbleView::WindowClosing' function.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct  denial of
service, execute an arbitrary code, trigger a sync with an arbitrary Google
account and other impacts.");
  script_tag(name:"affected", value:"Google Chrome version prior to 32.0.1700.77 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to version 32.0.1700.77 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56248");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64805");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64981");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029611");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/01/stable-channel-update.html");
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

if(version_is_less(version:chromeVer, test_version:"32.0.1700.77"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"32.0.1700.77");
  security_message(port:0, data:report);
  exit(0);
}
