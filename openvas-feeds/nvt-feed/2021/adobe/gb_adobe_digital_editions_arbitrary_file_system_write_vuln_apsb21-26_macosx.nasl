# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818042");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2021-21100");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 21:40:00 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-15 15:59:45 +0530 (Thu, 15 Apr 2021)");
  script_name("Adobe Digital Editions Arbitrary File System Write Vulnerability (APSB21-26) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to arbitrary file system write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to privilege escalation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  gain privilege escalation.");

  script_tag(name:"affected", value:"Adobe Digital Edition version
  4.5.11.187245 and below on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.11.187606 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb21-26.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_macosx.nasl");
  script_mandatory_keys("AdobeDigitalEdition/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
digitalVer = infos["version"];
digitalPath = infos["location"];

if(version_is_less(version:digitalVer, test_version:"4.5.11.187606"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.11.187606", install_path:digitalPath);
  security_message(data:report);
  exit(0);
}
exit(0);

