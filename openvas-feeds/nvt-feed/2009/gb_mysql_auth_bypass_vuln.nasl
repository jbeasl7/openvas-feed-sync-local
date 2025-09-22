# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801066");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4030");
  script_name("MySQL Authenticated Access Restrictions Bypass Vulnerability");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=32167");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-41.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow users to bypass intended access restrictions
  by calling CREATE TABLE with DATA DIRECTORY or INDEX DIRECTORY argument referring to a subdirectory.");

  script_tag(name:"affected", value:"MySQL 5.1.x before 5.1.41 on all running platform.");

  script_tag(name:"insight", value:"The flaw is due to an error while calling CREATE TABLE on a MyISAM table with modified
  DATA DIRECTORY or INDEX DIRECTORY.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.41 or later.");

  script_tag(name:"summary", value:"MySQL is prone to Access restrictions Bypass Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");


  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

version = eregmatch(pattern:"([0-9.a-z]+)", string:version);
if(version[1] && version_in_range(version:version[1], test_version:"5.1",test_version2:"5.1.40")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.1.41");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
