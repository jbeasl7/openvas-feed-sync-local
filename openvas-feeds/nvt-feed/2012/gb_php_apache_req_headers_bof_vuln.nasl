# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902837");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-2329");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-05-23 16:16:16 +0530 (Wed, 23 May 2012)");
  script_name("PHP 'apache_request_headers()' Function Buffer Overflow Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49014");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=61807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53455");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.4.3");
  script_xref(name:"URL", value:"http://www.php.net/archive/2012.php#id2012-05-08-1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=820000");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service.");

  script_tag(name:"affected", value:"PHP Version 5.4.x before 5.4.3 on Windows");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'apache_request_headers()'
  function, which can be exploited to cause a denial of service via a long
  string in the header of an HTTP request.");

  script_tag(name:"solution", value:"Update to PHP Version 5.4.3 or later.");

  script_tag(name:"summary", value:"PHP is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version: "5.4.0", test_version2: "5.4.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.4.3");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
