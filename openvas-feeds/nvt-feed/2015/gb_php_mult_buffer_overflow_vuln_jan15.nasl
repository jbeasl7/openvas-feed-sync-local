# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805410");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2015-01-06 17:55:40 +0530 (Tue, 06 Jan 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-8626");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.2.x < 5.2.7 Buffer Overflow Vulnerability (Jan 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stack-based buffer overflow in the date_from_ISO8601 function
  in ext/xmlrpc/libxmlrpc/xmlrpc.c allows remote attackers to cause a denial of service (application
  crash) or possibly execute arbitrary code by including a timezone field in a date, leading to
  improper XML-RPC encoding.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"PHP versions 5.2.x before 5.2.7");

  script_tag(name:"solution", value:"Update to version 5.2.7 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=45226");
  script_xref(name:"URL", value:"https://web.archive.org/web/20141109060712/http://www.securityfocus.com/bid/70928");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/11/06/3");

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

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
