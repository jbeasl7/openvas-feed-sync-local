# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804412");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2013-1893", "CVE-2013-1890");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-03-14 13:43:56 +0530 (Fri, 14 Mar 2014)");
  script_name("ownCloud Multiple XSS and SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"ownCloud is prone to multiple XSS and SQL injection vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"- Input passed via the 'new_name' POST parameter to
   /apps/bookmarks/ajax/renameTag.php is not properly sanitised before
   being used.

  - Certain unspecified input passed to some files in apps/contacts/ajax/ is not
   properly sanitised before being used.

  - Certain unspecified input passed to addressbookprovider.php is not properly
   sanitised before being used in a SQL query.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to inject or manipulate
SQL queries in the back-end database or conduct script insertion.");
  script_tag(name:"affected", value:"ownCloud Server before version 5.0.1");
  script_tag(name:"solution", value:"Update to version 5.0.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52833");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58855");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/83253");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-012");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"5.0.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.0.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
