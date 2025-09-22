# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804411");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2013-2045");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-03-14 13:35:19 +0530 (Fri, 14 Mar 2014)");
  script_name("ownCloud 'lib/db.php' SQL Injection Vulnerability");

  script_tag(name:"summary", value:"ownCloud is prone to an SQL injection (SQLi) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to the 'lib/db.php' script not properly sanitizing user
supplied input before using it in SQL queries.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data.");
  script_tag(name:"affected", value:"ownCloud Server 5.0.x before 5.0.6");
  script_tag(name:"solution", value:"Upgrade to ownCloud 5.0.6 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q2/324");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59961");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-019");
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

if(version_in_range(version:version, test_version:"5.0", test_version2:"5.0.5")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"5.0 - 5.0.5");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
