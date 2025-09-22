# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803981");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2006-0327");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-12-20 15:01:13 +0530 (Fri, 20 Dec 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_xref(name:"URL", value:"http://forge.typo3.org/issues/15402");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/24244");

  script_name("TYPO3 < 4.0 Path/Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"TYPO3 is prone to path/information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in the application which fails to properly
  determine its own physical path and therefore trying to 'require()' a wrong class file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  full installation path to the application.");

  script_tag(name:"affected", value:"TYPO3 version 3.7.1 and prior.");

  script_tag(name:"solution", value:"Update to version 4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# nb: No need for a "version_regex:" here because the VT is checking for < 4.0 which works if e.g.
# only version "3" was extracted
if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
