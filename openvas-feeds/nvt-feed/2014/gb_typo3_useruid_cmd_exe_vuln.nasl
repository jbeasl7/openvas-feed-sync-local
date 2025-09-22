# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804221");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2006-6690");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-01-09 17:58:28 +0530 (Thu, 09 Jan 2014)");
  script_name("TYPO3 userUid Command Execution Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in the rtehtmlarea extension, which fails to properly
  validate user supplied input to 'userUid' parameter");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"TYPO3 is prone to a command execution vulnerability.");

  script_tag(name:"affected", value:"TYPO3 version before 4.0.3");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/31061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21680");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

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

if(version_is_less(version:vers, test_version:"4.0.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.0.4", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
