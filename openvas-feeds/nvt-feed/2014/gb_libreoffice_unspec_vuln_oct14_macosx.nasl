# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804929");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-0247");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-10-01 12:57:54 +0530 (Wed, 01 Oct 2014)");

  script_name("LibreOffice Unspecified Vulnerability (Oct 2014) - Mac OS X");

  script_tag(name:"summary", value:"LibreOffice is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to the application not
  properly restricting VBA macros in the VBAProject element.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass certain security restrictions and execute VBA script code without
  user approval.");

  script_tag(name:"affected", value:"LibreOffice version 4.1.4/4.2.0 prior
  to 4.2.5 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to LibreOffice 4.2.5 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68151");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2014-0247");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!libreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:libreVer, test_version:"4.1.4", test_version2:"4.2.4"))
{
  report = report_fixed_ver(installed_version:libreVer, vulnerable_range:"4.1.4 - 4.2.4");
  security_message(port:0, data:report);
  exit(0);
}
