# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804393");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2006-5857", "CVE-2007-0046", "CVE-2007-0047", "CVE-2007-0044");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-11 18:00:34 +0530 (Fri, 11 Apr 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities (Jan 2007) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws exist due to:

  - Input passed to a hosted PDF file is not properly sanitised by the browser
plug-in before being returned to users.

  - Input passed to a hosted PDF file is not properly handled by the browser
plug-in.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause memory corruption,
execution of arbitrary code, execution of arbitrary script code in a user's
browser session in context of an affected site and conduct cross site request
forgery attacks.");
  script_tag(name:"affected", value:"Adobe Reader version 7.0.8 and prior on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 7.0.9 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/23483");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21981");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/31266");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb07-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"7.0.8")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 7.0.8");
  security_message(port:0, data:report);
  exit(0);
}
