# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804114");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2013-2928", "CVE-2013-2925", "CVE-2013-2926", "CVE-2013-2927");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-10-23 14:30:38 +0530 (Wed, 23 Oct 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-02 (Oct 2013) - Windows");


  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 30.0.1599.101 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use-after-free vulnerability in the HTMLFormElement 'prepareForSubmission'
function in core/html/HTMLFormElement.cpp.

  - Use-after-free vulnerability in the IndentOutdentCommand
'tryIndentingAsListItem' function in core/editing/IndentOutdentCommand.cpp.

  - Use-after-free vulnerability in core/xml/XMLHttpRequest.cpp.

  - Another unspecified error.");
  script_tag(name:"affected", value:"Google Chrome before 30.0.1599.101");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
service or possibly have other impact via vectors related to submission
for FORM elements, vectors related to list elements, vectors that trigger
multiple conflicting uses of the same XMLHttpRequest object or via unknown
vectors.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63024");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63028");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/446283.php");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/10/stable-channel-update_15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(version_is_less(version:chromeVer, test_version:"30.0.1599.101"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"30.0.1599.101");
  security_message(port: 0, data: report);
  exit(0);
}
