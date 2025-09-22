# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804211");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2011-4900");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-07 20:26:00 +0000 (Thu, 07 Nov 2019)");
  script_tag(name:"creation_date", value:"2014-01-07 16:14:54 +0530 (Tue, 07 Jan 2014)");
  script_name("TYPO3 < 4.5.4 Backend Editor Information Disclosure Vulnerability (TYPO3-CORE-SA-2011-001)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2011-001");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45557/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49072");

  script_tag(name:"summary", value:"TYPO3 is prone to an authorization bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in backend editor, which allows to see workspace
  changes of records without authorized access.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to get
  sensitive information.");

  script_tag(name:"affected", value:"TYPO3 versions prior to 4.5.4.");

  script_tag(name:"solution", value:"Update to version 4.5.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"4.5.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.5.4", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
