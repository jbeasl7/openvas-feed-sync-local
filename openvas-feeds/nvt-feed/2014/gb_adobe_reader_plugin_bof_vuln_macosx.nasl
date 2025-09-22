# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804258");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2005-2470");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-15 18:50:55 +0530 (Tue, 15 Apr 2014)");
  script_name("Adobe Reader 'Plug-in' Buffer Overflow Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader is prone to a buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exists due to an unspecified boundary error in the core application
plug-in.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct denial of service and
possibly execute arbitrary code.");
  script_tag(name:"affected", value:"Adobe Reader version 5.1, 6.x through 6.0.3, 7.x through 7.0.2 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader 6.0.4 or 7.0.5 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/16466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14603");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1014712");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/321644.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_equal(version:vers, test_version:"5.1")||
   version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3")||
   version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.2")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
