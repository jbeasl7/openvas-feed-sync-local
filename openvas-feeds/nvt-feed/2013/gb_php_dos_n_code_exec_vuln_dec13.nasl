# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804174");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2013-12-19 18:09:47 +0530 (Thu, 19 Dec 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-6420");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.28, 5.4.x < 5.4.23, 5.5.x < 5.5.7 RCE Vulnerability (Dec 2013)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A boundary error exists within the 'asn1_time_to_time_t'
  function in 'ext/openssl/openssl.c' when parsing X.509 certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption).");

  script_tag(name:"affected", value:"PHP versions before 5.3.28, 5.4.x before 5.4.23, and 5.5.x
  before 5.5.7.");

  script_tag(name:"solution", value:"Update to version 5.3.28, 5.4.23, 5.5.7 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56055");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124436/PHP-openssl_x509_parse-Memory-Corruption.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.3.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5.0", test_version2: "5.5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
