# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809247");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-4256", "CVE-2016-4257", "CVE-2016-4258", "CVE-2016-4259",
                "CVE-2016-4260", "CVE-2016-4261", "CVE-2016-4262", "CVE-2016-4263",
                "CVE-2016-6980");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");
  script_tag(name:"creation_date", value:"2016-09-15 11:53:23 +0530 (Thu, 15 Sep 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Digital Editions Multiple Code Execution Vulnerabilities (Sep 2016) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The multiple memory corruption vulnerabilities.

  - An use-after-free vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Digital Edition 4.x before 4.5.2 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version 4.5.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb16-28.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92928");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93179");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_macosx.nasl");
  script_mandatory_keys("AdobeDigitalEdition/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!digitalVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:digitalVer, test_version:"4.0.0", test_version2:"4.5.1"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.2");
  security_message(data:report);
  exit(0);
}
