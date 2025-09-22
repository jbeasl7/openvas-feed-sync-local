# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902595");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2010-5054");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-12-13 12:12:12 +0530 (Tue, 13 Dec 2011)");
  script_name("JAMWiki 'message' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39335");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39225");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57630");
  script_xref(name:"URL", value:"http://jamwiki.svn.sourceforge.net/viewvc/jamwiki/wiki/branches/0.8.x/jamwiki-war/src/main/webapp/CHANGELOG.txt?view=markup&revision=2995");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"JAMWiki versions prior to 0.8.4.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input to the
  'message' parameter via Special:Login in error.jsp, which allows attackers
  to execute arbitrary HTML and script code in a user's browser session in
  the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to JAMWiki version 0.8.4 or later.");

  script_tag(name:"summary", value:"JAMWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:8080);

foreach dir (make_list_unique("/jamwiki", "/JAMWiki", "/wiki", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/en/StartingPoints", port:port);
  if('>JAMWiki<' >< res)
  {
    url = dir + "/en/Special:Login?message=><script>alert(document.cookie)" +
                "</script>";

    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"><script>alert\(document.cookie\)</script>"))
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
