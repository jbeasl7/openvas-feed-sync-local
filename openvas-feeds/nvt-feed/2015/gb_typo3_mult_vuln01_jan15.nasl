# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805247");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2014-9508", "CVE-2014-9509");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-19 12:19:42 +0530 (Mon, 19 Jan 2015)");
  script_name("TYPO3 Multiple Vulnerabilities (TYPO3-CORE-SA-2014-003)");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Certain input passed to the homepage is not properly sanitised before being
    used to generate anchor links.

  - An error related to the 'config.prefixLocalAnchors' configuration option.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to poison the cache and conduct spoofing attacks.");

  script_tag(name:"affected", value:"TYPO3 versions 4.5.x before 4.5.39, 4.6.x
  through 6.2.x before 6.2.9, and 7.x before 7.0.2");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.39 or 6.2.9
  or 7.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60371");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2014-003");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.38") ||
   version_in_range(version:vers, test_version:"4.6.0", test_version2:"6.2.8") ||
   version_in_range(version:vers, test_version:"7.0.0", test_version2:"7.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.5.39/6.2.9/7.0.2", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
