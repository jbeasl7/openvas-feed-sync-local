# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802621");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-04-02 11:11:11 +0530 (Mon, 02 Apr 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2012-1983");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("JamWiki < 1.1.6 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"JAMWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied
  input to the 'num' parameter in Special:AllPages, which allows attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"JAMWiki prior to version 1.1.6.");

  script_tag(name:"solution", value:"Update to version 1.1.6 or later.");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=493");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52829");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48638");
  script_xref(name:"URL", value:"http://jamwiki.org/wiki/en/JAMWiki_1.1.6");
  script_xref(name:"URL", value:"http://jira.jamwiki.org/browse/JAMWIKI-76");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_JamWiki_XSS_Vuln.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111410/jamwiki-xss.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

foreach dir (make_list_unique("/", "/jamwiki", "/JAMWiki", "/wiki", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/en/StartingPoints");
  if (res !~ "^HTTP/1\.[01] 200" || ">JAMWiki<" >!< res)
    continue;

  url = dir + '/en/Special:AllPages?num="<script>alert(document.cookie)</script>';

  if (http_vuln_check(port: port, url: url, check_header: TRUE,
                      pattern: "<script>alert\(document.cookie\)</script>")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
