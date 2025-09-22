# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805245");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-0301", "CVE-2015-0302", "CVE-2015-0303", "CVE-2015-0304",
                "CVE-2015-0305", "CVE-2015-0306", "CVE-2015-0307", "CVE-2015-0308",
                "CVE-2015-0309");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-16 13:17:39 +0530 (Fri, 16 Jan 2015)");
  script_name("Adobe AIR Multiple Vulnerabilities-01 (Jan 2015) - Windows");

  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An unspecified error related to improper file validation.

  - Another unspecified error which can be exploited to capture keystrokes.

  - Two unspecified errors which can be exploited to corrupt memory.

  - Two unspecified errors which can be exploited to cause a heap-based
  buffer overflow.

  - A type confusion error which can be exploited to corrupt memory.

  - An out-of-bounds read error.

  - An unspecified use-after-free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to disclose potentially sensitive information and
  compromise a user's system.");

  script_tag(name:"affected", value:"Adobe AIR before version 16.0.0.245
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Adobe AIR version 16.0.0.245
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62177");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72035");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72032");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72039");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72038");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb15-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"16.0.0.245")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"16.0.0.245");
  security_message(port: 0, data: report);
  exit(0);
}
