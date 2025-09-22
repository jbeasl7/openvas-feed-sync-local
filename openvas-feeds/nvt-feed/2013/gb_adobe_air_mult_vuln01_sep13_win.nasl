# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804000");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-5324", "CVE-2013-3361", "CVE-2013-3362", "CVE-2013-3363");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-09-18 19:10:43 +0530 (Wed, 18 Sep 2013)");
  script_name("Adobe AIR Multiple Vulnerabilities-01 (Sep 2013) - Windows");


  script_tag(name:"summary", value:"Adobe AIR is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe AIR version 3.8.0.1430 or later.");
  script_tag(name:"insight", value:"Flaws are due to multiple unspecified errors.");
  script_tag(name:"affected", value:"Adobe AIR before 3.8.0.1430 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption and compromise a user's system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54697");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62290");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62296");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb13-21.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"3.8.0.1430")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.8.0.1430");
  security_message(port: 0, data: report);
  exit(0);
}
