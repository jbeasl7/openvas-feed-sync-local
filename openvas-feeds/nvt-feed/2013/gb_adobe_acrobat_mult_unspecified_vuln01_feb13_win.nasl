# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803418");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-02-19 19:28:21 +0530 (Tue, 19 Feb 2013)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0640", "CVE-2013-0641");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:36:05 +0000 (Tue, 16 Jul 2024)");
  script_name("Adobe Acrobat Multiple Unspecified Vulnerabilities -01 (Feb 2013) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57931");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57947");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa13-02.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2013/02/adobe-reader-and-acrobat-vulnerability-report.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  script_tag(name:"affected", value:"Adobe Acrobat Version 9.x prior to 9.5.4 on Windows

Adobe Acrobat X Version 10.x prior to 10.1.6 on Windows

Adobe Acrobat XI Version 11.x prior to 11.0.02 on Windows");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors.");
  script_tag(name:"solution", value:"Upgrade to version 9.5.4 or X (10.1.6) or XI (11.0.02) or later.");
  script_tag(name:"summary", value:"Adobe Acrobat is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
code or cause a denial of service via a crafted PDF document.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"9.0", test_version2: "9.5.3" ) ||
    version_in_range( version:vers, test_version:"10.0", test_version2: "10.1.5") ||
    version_in_range( version:vers, test_version:"11.0", test_version2: "11.0.01" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.5.4 / X (10.1.6) / XI (11.0.02)", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
