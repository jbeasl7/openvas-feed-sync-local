# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901093");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-01-04 15:26:56 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4484");
  script_name("MySQL Server Buffer Overflow Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38364");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-1.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-43.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.0/en/news-5-0-90.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute
arbitrary code.");
  script_tag(name:"affected", value:"MySQL Version 5.0.x before 5.0.90, MySQL version 5.1.x before
5.1.43, MySQL 5.5.x through 5.5.0-m2 On Linux");
  script_tag(name:"insight", value:"The flaw is due to an error in application that allows remote
attackers to execute arbitrary code via unspecified vectors");
  script_tag(name:"solution", value:"Upgrade to MySQL Version 5.0.90 or 5.1.43 or 5.5.1 or later.");
  script_tag(name:"summary", value:"MySQL is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

sqlPort = get_app_port(cpe:CPE);
if(!sqlPort){
  exit(0);
}

mysqlVer = get_app_version(cpe:CPE, port:sqlPort);
if(isnull(mysqlVer)){
  exit(0);
}

mysqlVer = eregmatch(pattern:"([0-9.a-z]+)", string:mysqlVer);
if(!isnull(mysqlVer[1]))
{
  if(version_in_range(version:mysqlVer[1], test_version:"5.0.0", test_version2:"5.0.89")||
     version_in_range(version:mysqlVer[1], test_version:"5.1.0", test_version2:"5.1.42")||
     version_in_range(version:mysqlVer[1], test_version:"5.5.0", test_version2:"5.5.0.m2")){
    security_message(port:sqlPort);
  }
}
