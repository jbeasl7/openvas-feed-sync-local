# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801453");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2009-4994", "CVE-2009-4995");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("SmarterTools SmarterTrack XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36172");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52305");
  script_xref(name:"URL", value:"http://holisticinfosec.org/content/view/123/45/");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 9996);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are due to the input passed to the 'search' parameter in
  'frmKBSearch.aspx' and email address to 'frmTickets.aspx' is not properly
  sanitised before being returned to the user.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to SmarterTools SmarterTrack version 4.0.3504.");

  script_tag(name:"summary", value:"SmarterTools SmarterTrack is prone to cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"SmarterTools SmarterTrack version prior to 4.0.3504.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:9996);
if(!http_can_host_asp(port:port))
  exit(0);

res = http_get_cache(item:"/Main/Default.aspx", port:port);
if(!res || ">SmarterTrack" >!< res)
  exit(0);

url = "/Main/frmKBSearch.aspx?search=%3Cscript%3Ealert(%22VT-XSS-Test%22)%3C/script%3E";

req = http_get(port:port, item:url);
res = http_keepalive_send_recv(port:port, data:req);
if(res =~ "^HTTP/1\.[01] 200" && '<script>alert("VT-XSS-Test")</script>' >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
