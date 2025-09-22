# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800145");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5214", "CVE-2008-5215");
  script_name("ClanLite SQL Injection and Cross-Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5595");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29156");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/42331");

  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary scripting code or
  SQL commands in the context of an affected application, which allows an
  attacker to steal cookie-based authentication credentials or access and modify data.");

  script_tag(name:"affected", value:"ClanLite Version 2.2006.05.20 and prior.");

  script_tag(name:"insight", value:"The flaws are due to error in service/calendrier.php and
  service/profil.php which are not properly sanitized before being used.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"ClanLite is prone to SQL injection (SQLi) and cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/clanlite", http_cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir + "/service/index_pri.php"), port:port);
  if(!rcvRes)
    continue;

  if("<title>ClanLite" >< rcvRes)
  {
    if(safe_checks())
    {
      clVer = eregmatch(pattern:"ClanLite<.+ V([0-9.]+)", string:rcvRes);
      if(clVer[1] != NULL) {
        if(version_is_less_equal(version:clVer[1], test_version:"2.2006.05.20")){
          security_message(port:port);
        }
      }
      exit(0);
    }

    url = string(dir + "/service/calendrier.php?mois=6&annee='><script>alert(document.cookie)</script>");
    sndReq = http_get(item:url, port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);
    if(!rcvRes)
      continue;

    if("<script>alert(document.cookie)</script>" >< rcvRes){
      security_message(port:port);
    }
    exit(0);
  }
}

exit(99);
