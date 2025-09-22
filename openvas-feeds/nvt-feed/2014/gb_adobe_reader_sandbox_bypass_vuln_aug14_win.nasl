# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804813");
  script_version("2024-07-01T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0546");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:39 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 17:28:59 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-08-19 12:05:17 +0530 (Tue, 19 Aug 2014)");
  script_name("Adobe Reader Sandbox Bypass Vulnerability (Aug 2014) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to a sandbox bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exists due to some unspecified error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass sandbox restrictions
and execute native code in a privileged context.");
  script_tag(name:"affected", value:"Adobe Reader X version 10.x before 10.1.11 and XI version 11.x before 11.0.08
on Windows.");
  script_tag(name:"solution", value:"Upgrade to version 10.1.11 or 11.0.08 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/reader/apsb14-19.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69193");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^1[01]\.") {
  if((version_in_range(version:vers, test_version:"10.0", test_version2: "10.1.10"))||
     (version_in_range(version:vers, test_version:"11.0", test_version2: "11.0.07")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
