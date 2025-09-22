# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808272");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-5385");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-29 16:17:00 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-07-27 10:28:48 +0530 (Wed, 27 Jul 2016)");
  script_name("TYPO3 Environment Variable Injection Vulnerability (Jul 2016)");

  script_tag(name:"summary", value:"TYPO3 is prone to an environment variable injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to PHP, when used as
  CGI, FPM or HHVM, exposes http headers also as environment variables starting
  with 'HTTP_'.TYPO3 is vulnerable through third party library guzzlehttp/guzzle
  which makes use of the environment variable 'HTTP_PROXY'.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to conduct MITM attacks on internal server subrequests
  or direct the server to initiate connections to arbitrary hosts.");

  script_tag(name:"affected", value:"TYPO3 versions 8.0.0 to 8.2.0");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 8.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-019");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91821");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(vers =~ "^8\." && version_in_range(version:vers, test_version:"8.0", test_version2:"8.2.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.2.1", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
