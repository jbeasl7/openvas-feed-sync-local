# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804746");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-0538", "CVE-2014-0540", "CVE-2014-0541", "CVE-2014-0542",
                "CVE-2014-0543", "CVE-2014-0544", "CVE-2014-0545", "CVE-2014-5333");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-08-19 15:11:46 +0530 (Tue, 19 Aug 2014)");
  script_name("Adobe AIR Multiple Vulnerabilities-01 (Aug 2014) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to an unspecified error and an use-after-free error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe AIR before version 14.0.0.178 on Mac OS X.");
  script_tag(name:"solution", value:"Update to Adobe AIR version 14.0.0.178 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58593");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69190");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69191");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69192");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69195");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69197");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69320");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"14.0.0.178")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"14.0.0.178");
  security_message(port:0, data:report);
  exit(0);
}
