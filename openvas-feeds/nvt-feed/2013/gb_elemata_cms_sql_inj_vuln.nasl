# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903311");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-06-27 10:38:15 +0530 (Thu, 27 Jun 2013)");
  script_name("Elemata CMS SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://1337day.com/exploit/20927");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26416");
  script_xref(name:"URL", value:"http://toexploit.com/exploit/na/elemata-cms-rc30-sql-injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may leads to access
  or modify data in the underlying database.");

  script_tag(name:"affected", value:"Elemata CMS version RC3.0");

  script_tag(name:"insight", value:"The flaw is due to improper validation of input passed via
  the 'id' parameter in index.php script.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Elemata CMS is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/elemata", "/cms", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && "Elemata CMS<" >< res && "Management System<" >< res ) {

    url = dir + "/index.php?id='SQL-Injection-Test";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"You have an error in your SQL syntax.*SQL-Injection-Test"))
    {
      security_message(port);
      exit(0);
    }
  }
}

exit(99);
