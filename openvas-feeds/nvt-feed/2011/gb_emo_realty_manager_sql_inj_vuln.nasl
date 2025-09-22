# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802342");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2010-5006");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-11-09 16:19:55 +0530 (Wed, 09 Nov 2011)");
  script_name("EMO Realty Manager 'cat1' Parameter SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://securityreason.com/securityalert/8505");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40625");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/90411/emorealtymanager-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL
  injection attack and gain sensitive information.");

  script_tag(name:"affected", value:"EMO Realty Manager Software.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  passed via the 'cat1' parameter to 'googlemap/index.php', which allows attackers
  to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"EMO Realty Manager Software is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir(make_list_unique("/emo_virtual", "/emorealty", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if('<title>EMO Realty Manager' >< res)
  {
    url = string(dir, "/googlemap/index.php?cat1='");

    if(http_vuln_check(port:port, url:url, pattern:'You have an error' +
                      ' in your SQL syntax;', check_header: FALSE))
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
