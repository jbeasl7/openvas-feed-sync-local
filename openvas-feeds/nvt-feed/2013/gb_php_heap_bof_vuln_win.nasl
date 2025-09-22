# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803342");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-2386");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-03-21 18:05:46 +0530 (Thu, 21 Mar 2013)");
  script_name("PHP 'phar/tar.c' Heap Buffer Overflow Vulnerability - Windows");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47545");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/426726.php");
  script_xref(name:"URL", value:"http://secunia.com/advisories/cve_reference/CVE-2012-2386");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  or cause a denial-of-service condition via specially crafted TAR file.");

  script_tag(name:"affected", value:"PHP version before 5.3.14 and 5.4.x before 5.4.4");

  script_tag(name:"insight", value:"Flaw related to overflow in phar_parse_tarfile()function in ext/phar/tar.c
  in the phar extension.");

  script_tag(name:"solution", value:"Update to PHP 5.4.4 or 5.3.14 or later.");

  script_tag(name:"summary", value:"PHP is prone to a heap buffer overflow vulnerability.");

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

if(version_is_less(version:vers, test_version:"5.3.14")||
  version_in_range(version:vers, test_version:"5.4", test_version2: "5.4.3")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.14/5.4.4");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
