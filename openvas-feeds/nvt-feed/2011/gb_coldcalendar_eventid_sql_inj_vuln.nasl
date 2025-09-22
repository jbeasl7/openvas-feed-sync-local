# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802253");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2010-4910");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ColdGen ColdCalendar 'EventID' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41333");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43035");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61637");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14932/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/93557/coldcalendar-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"ColdGen ColdCalendar version 2.06.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'EventID' parameter in index.cfm, which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"ColdGen ColdCalendar is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/coldcal", "/coldcalendar", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.cfm", port:port);
  if("<title>ColdCalendar" >< res)
  {
    url = dir + "/index.cfm?fuseaction=ViewEventDetails&EventID=1+and+1";

    if(http_vuln_check(port:port, url:url, pattern:"Error Executing Database " +
       "Query", extra_check: make_list('SELECT *', 'WHERE EventID = 1 and 1')))
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
