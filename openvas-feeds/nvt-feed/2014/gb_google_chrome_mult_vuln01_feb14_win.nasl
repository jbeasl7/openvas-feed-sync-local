# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804305");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2014-1681", "CVE-2013-6650", "CVE-2013-6649");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-02-03 13:43:16 +0530 (Mon, 03 Feb 2014)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Feb 2014) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A use-after-free error exists within 'RenderSVGImage::paint' function in
Blink.

  - An error related to v8 within 'StoreBuffer::ExemptPopularPages' function.

  - Many unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
service, execute an arbitrary code and other unspecified impacts.");
  script_tag(name:"affected", value:"Google Chrome version prior to 32.0.1700.102 on Windows.");
  script_tag(name:"solution", value:"Upgrade to version 32.0.1700.102 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56640");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65168");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65232");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/01/stable-channel-update_27.html");
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

if(version_is_less(version:chromeVer, test_version:"32.0.1700.102"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"32.0.1700.102");
  security_message(port:0, data:report);
  exit(0);
}
