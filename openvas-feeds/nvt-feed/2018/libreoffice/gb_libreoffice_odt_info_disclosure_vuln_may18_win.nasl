# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812872");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-10583");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-21 13:15:00 +0000 (Wed, 21 Oct 2020)");
  script_tag(name:"creation_date", value:"2018-05-07 13:33:47 +0530 (Mon, 07 May 2018)");
  script_tag(name:"qod_type", value:"registry");

  script_name("LibreOffice ODT File Information Disclosure Vulnerability (May 2018) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within an office:document-content element in a .odt XML
document.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to automatically process and
initiate an SMB connection embedded in a malicious .odt file and leak NetNTLM credentials.");

  script_tag(name:"affected", value:"LibreOffice prior to version 5.4.7 or 6.0.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.4.7, 6.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secureyourit.co.uk/wp/2018/05/01/creating-malicious-odt-files/");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-10583/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
lver = infos["version"];
lpath = infos["location"];

if (version_is_less(version: lver, test_version: "5.4.7")) {
  report = report_fixed_ver(installed_version:lver, fixed_version:"5.4.7", install_path:lpath);
  security_message(port: 0, data:report);
  exit(0);
}

if (lver =~ "^6\.0") {
  if (version_is_less(version: lver, test_version: "6.0.4")) {
    report = report_fixed_ver(installed_version:lver, fixed_version:"6.0.4", install_path:lpath);
    security_message(port: 0, data:report);
    exit(0);
  }
}

exit(0);
