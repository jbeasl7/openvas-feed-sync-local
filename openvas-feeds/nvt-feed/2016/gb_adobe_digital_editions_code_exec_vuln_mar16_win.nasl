# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807473");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2016-0954");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-03-10 11:12:19 +0530 (Thu, 10 Mar 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Editions Code Execution Vulnerability (APSB16-06) - Windows");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to a code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to memory leak vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code.");

  script_tag(name:"affected", value:"Adobe Digital Edition 4.x before 4.5.1.");

  script_tag(name:"solution", value:"Update to version 4.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb16-06.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.5.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.5.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
