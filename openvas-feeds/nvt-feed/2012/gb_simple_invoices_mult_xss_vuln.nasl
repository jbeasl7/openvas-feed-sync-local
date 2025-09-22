# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803073");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2012-4932");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-12-11 13:59:06 +0530 (Tue, 11 Dec 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Simple Invoices Multiple XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 8877);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80625");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56882");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Dec/73");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118737/simpleinvoices-xss.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed.");

  script_tag(name:"affected", value:"Simple Invoices version 2011.1 and prior");

  script_tag(name:"insight", value:"Input passed via the 'having' parameter to index.php
  (when 'module' and 'view' are set to different actions) is not properly
  sanitised before it is returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Simple Invoices version 2012-1 or later.");

  script_tag(name:"summary", value:"Simple Invoices is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.simpleinvoices.org/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

siPort = http_get_port(default:8877);

if(!http_can_host_php(port:siPort)){
  exit(0);
}

foreach dir (make_list_unique("/simpleinvoices", "/invoice", "/", http_cgi_dirs(port:siPort)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:siPort );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">Simple Invoices" >< res && '>Dashboard' >< res &&
      '>Settings' >< res ) {

    url = url + '?module=invoices&view=manage&having=' +
                '<script>alert(document.cookie)</script>';

    if(http_vuln_check(port:siPort, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document\.cookie\)</script>",
                       extra_check:make_list('>Simple Invoices', '>Dashboard')))
    {
      security_message(port:siPort);
      exit(0);
    }
  }
}

exit(99);
