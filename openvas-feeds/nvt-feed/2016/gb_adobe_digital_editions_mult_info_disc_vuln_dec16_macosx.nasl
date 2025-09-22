# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809835");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-7888", "CVE-2016-7889");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 23:25:00 +0000 (Thu, 22 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-12-15 11:17:23 +0530 (Thu, 15 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Digital Editions Multiple Vulnerabilities (Dec 2016) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when parsing XML external entities.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information and this may lead to further attacks.");

  script_tag(name:"affected", value:"Adobe Digital Edition prior to 4.5.3");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb16-45.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94879");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94880");
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

if(version_is_less(version:digitalVer, test_version:"4.5.3"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.3");
  security_message(data:report);
  exit(0);
}
