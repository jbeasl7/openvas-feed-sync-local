# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807082");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-1629");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-02-15 12:12:26 +0530 (Mon, 15 Feb 2016)");
  script_name("Google Chrome Security Bypass Vulnerability (Feb 2016) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  Same Origin Policy and a Sandbox protection.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote
  attckers to bypass the same-origin policy and certain access restrictions to
  access data, or execute arbitrary script code and this could be used to steal
  sensitive information or launch other attacks.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  48.0.2564.116 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  48.0.2564.116 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/02/stable-channel-update_18.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83302");

  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:chromeVer, test_version:"48.0.2564.116"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"48.0.2564.116");
  security_message(data:report);
  exit(0);
}
