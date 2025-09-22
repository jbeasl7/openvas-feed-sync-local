# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804374");
  script_version("2024-07-01T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2008-0667", "CVE-2007-5666", "CVE-2007-5659", "CVE-2007-5663",
                "CVE-2008-0726", "CVE-2008-0655", "CVE-2008-2042");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:39 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:15:34 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-04-08 19:38:29 +0530 (Tue, 08 Apr 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities (Feb 2008) - Linux");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to:

  - Multiple boundary errors in several unspecified JavaScript methods.

  - An unspecified insecure JavaScript method in 'EScript.api'.

  - Untrusted search path error in 'Security Provider' libraries.

  - An error in insecure JavaScript method 'DOC.print'.

  - An integer overflow in the 'printSepsWithParams' JavaScript method.

  - An unspecified error in Javascript API.

  - Other unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct a denial of service
and execution of arbitrary code or compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Reader version 8.1.1 and earlier on Linux.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 8.1.2 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/28802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27641");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa08-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"8.1.1")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 8.1.1");
  security_message(port:0, data:report);
  exit(0);
}
