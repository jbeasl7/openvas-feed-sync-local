# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800051");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2008-2992", "CVE-2008-2549", "CVE-2008-4812",
                "CVE-2008-4813", "CVE-2008-4817", "CVE-2008-4816",
                "CVE-2008-4814", "CVE-2008-4815");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:41:48 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-11-05 13:21:04 +0100 (Wed, 05 Nov 2008)");
  script_name("Adobe Reader/Acrobat Multiple Vulnerabilities (APSB08-19) - Linux");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - a boundary error when parsing format strings containing a floating point
  specifier in the util.printf() Javascript function.

  - improper parsing of type 1 fonts.

  - bounds checking not being performed after allocating an area of memory.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code to
  cause a stack based overflow via a specially crafted PDF, and could also take
  complete control of the affected system and cause the application to crash.");

  script_tag(name:"affected", value:"Adobe Reader/Acrobat versions 8.1.2 and prior.");

  script_tag(name:"solution", value:"Upgrade to 8.1.3 or higher versions.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-19.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30035");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32100");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/adobe-reader-buffer-overflow");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!adobeVer = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:adobeVer, test_version:"8.1.2")) {
  report = report_fixed_ver(installed_version:adobeVer, vulnerable_range:"Less than or equal to 8.1.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
