# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805651");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-06-16 18:45:49 +0530 (Tue, 16 Jun 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-2331", "CVE-2015-2348", "CVE-2015-2787", "CVE-2015-4147",
                "CVE-2015-4148");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.4.39, 5.5.x < 5.5.23, 5.6.x < 5.6.7 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - 'do_soap_call' function in ext/soap/soap.c script in PHP does not verify that the uri property
  is a string.

  - 'SoapClient::__call' method in ext/soap/soap.c script in PHP does not verify that
  __default_headers is an array.

  - use-after-free error related to the 'unserialize' function when using DateInterval input.

  - a flaw in the 'move_uploaded_file' function that is triggered when handling NULL bytes.

  - an integer overflow condition in the '_zip_cdir_new' function in 'zip_dirent.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  obtain sensitive information by providing crafted serialized data with an int data type and to
  execute arbitrary code by providing crafted serialized data with an unexpected data type.");

  script_tag(name:"affected", value:"PHP prior to version 5.4.39, 5.5.x prior to 5.5.23 and 5.6.x
  prior to 5.6.7.");

  script_tag(name:"solution", value:"Update to version 5.4.39, 5.5.23, 5.6.7 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73357");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73434");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=69085");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/01/4");

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

if (version_is_less(version: version, test_version: "5.4.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5.0", test_version2: "5.5.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.6.0", test_version2: "5.6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
