# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804112");
  script_version("2024-02-26T14:36:40+0000");
  script_cve_id("CVE-2013-5325");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-10-18 08:57:35 +0530 (Fri, 18 Oct 2013)");
  script_name("Adobe Acrobat Remote Code Execution Vulnerability (APSB13-25) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe Acrobat version 11.0.05 or later.");
  script_tag(name:"insight", value:"The flaw is due to some error affecting javascript security controls.");
  script_tag(name:"affected", value:"Adobe Acrobat version 11.x before 11.0.05 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass the security controls
and execute arbitrary javascript code by launching javascript scheme URIs
when a PDF file is being viewed in a browser.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62888");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb13-25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!acrobatVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(acrobatVer =~ "^11\.0")
{
  if(version_in_range(version:acrobatVer, test_version:"11.0.0", test_version2:"11.0.04"))
  {
    report = report_fixed_ver(installed_version:acrobatVer, vulnerable_range:"11.0.0 - 11.0.04");
    security_message(port: 0, data: report);
    exit(0);
  }
}
