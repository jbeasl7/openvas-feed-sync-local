# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803739");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2013-4248");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-19 17:10:43 +0530 (Mon, 19 Aug 2013)");
  script_name("PHP SSL Certificate Validation Security Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"PHP is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to PHP version 5.4.18 or 5.5.2 or later.");

  script_tag(name:"insight", value:"The flaw is due to the SSL module not properly handling NULL bytes inside
  'subjectAltNames' general names in the server SSL certificate.");

  script_tag(name:"affected", value:"PHP versions before 5.4.18 and 5.5.x before 5.5.2 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof the server via
  a MitM (Man-in-the-Middle) attack and disclose potentially sensitive
  information.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54480");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61776");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=2874696a5a8d46639d261571f915c493cd875897");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"5.4.18") ||
   version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.1")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.4.18/5.5.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
