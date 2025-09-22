# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803826");
  script_version("2024-11-19T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-19 05:05:41 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"creation_date", value:"2013-07-08 14:53:58 +0530 (Mon, 08 Jul 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nameko Webmail <= 0.10.146 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Nameko Webmail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'fontsize' parameter to 'nameko.php' php
  script is not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Nameko Webmail version 0.10.146 and prior.");

  script_tag(name:"solution", value:"Update to version 1.9.999.10 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122221/Nameko_Webmail_XSS.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/nameko-webmail-cross-site-scripting");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/NamekoWebmail", "/webmail", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: "/nameko.php");

  if (">Nameko" >< res && "Shelf<" >< res) {
    url = dir + "/nameko.php?fontsize=22pt%3B%2B%7D%2B%3C%2Fstyle%3E%3C"+
                 "script%3Ealert%28document.cookie%29%3C%2Fscript%3E%3Cstyle%3Ebody%2B%7B%2Bfont-size%3A22";

    if (http_vuln_check(port: port, url: url, check_header: TRUE,
                        pattern: "<script>alert\(document.cookie\)</script>", extra_check: "font-size:22pt")) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
