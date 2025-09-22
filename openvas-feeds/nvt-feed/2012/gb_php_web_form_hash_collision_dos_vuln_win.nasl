# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802408");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2011-4885", "CVE-2012-0788", "CVE-2012-0789");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-01-03 16:47:40 +0530 (Tue, 03 Jan 2012)");
  script_name("PHP Web Form Hash Collision Denial of Service Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial
  of service via a specially crafted form sent in a HTTP POST request.");

  script_tag(name:"affected", value:"PHP Version 5.3.8 and prior.");

  script_tag(name:"insight", value:"The flaws are due to an error in,

  - A hash generation function when hashing form posts and updating a hash
    table. This can be exploited to cause a hash collision resulting in high
    CPU consumption via a specially crafted form sent in a HTTP POST request.

  - PDORow implementation, when interacting with the session feature.

  - timezone functionality, when handling php_date_parse_tzfile cache.");

  script_tag(name:"solution", value:"Update PHP to 5.3.9 or later.");

  script_tag(name:"summary", value:"PHP is prone to a remote denial of service vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47404");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51193");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51952");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52043");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/903934");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=53502");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=55776");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72021");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18305/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18296/");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=321040");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"5.3.8")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.9");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
