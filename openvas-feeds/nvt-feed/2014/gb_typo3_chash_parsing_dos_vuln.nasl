# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803995");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2011-3584");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-05 16:29:00 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2013-12-31 16:24:40 +0530 (Tue, 31 Dec 2013)");
  script_name("TYPO3 cHash Parsing Denial of Service Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service
  condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in TYPO3 because it fails to disable caching when
  an invalid cache hash URL parameter (cHash) is provided.");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.3.14 or 4.4.11 or 4.5.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"TYPO3 is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"affected", value:"TYPO3 versions 4.2.0 to 4.2.17, 4.3.0 to 4.3.13, 4.4.0 to 4.4.10 and 4.5.0 to
  4.5.5.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45940/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49622");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2011-003/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.17") ||
   version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.13") ||
   version_in_range(version:vers, test_version:"4.4.0", test_version2:"4.4.10") ||
   version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.3.14 / 4.4.11 / 4.5.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
