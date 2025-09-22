# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902691");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-5213", "CVE-2011-5214");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-10-30 12:15:54 +0530 (Tue, 30 Oct 2012)");
  script_name("BrowserCRM Multiple SQLi and XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47217");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51060");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71828");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23059");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to inputs passed via

  - The 'PATH_INFO' to index.php, modules/admin/admin_module_index.php, or
  modules/calendar/customise_calendar_times.php, 'login[]' parameter to
  index.php or pub/clients.php and 'framed' parameter to licence/index.php
  or licence/view.php is not properly verified before it is returned to
  the user.

  - The 'login[username]' parameter to index.php, 'parent_id' parameter to
  modules/Documents/version_list.php or 'contact_id' parameter to
  modules/Documents/index.php is not properly sanitized before being used
  in a SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"BrowserCRM is prone to multiple SQL injection (SQLi) and
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of an
  affected site and manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"BrowserCRM version 5.100.1 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

bcrmPort = http_get_port(default:80);

if(!http_can_host_php(port:bcrmPort)){
  exit(0);
}

foreach dir (make_list_unique("/browserCRM", "/browsercrm", "/browser", "/", http_cgi_dirs(port:bcrmPort)))
{
  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:bcrmPort );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">BrowserCRM<" >< res && 'please log in' >< res ) {

    url = url + '/"><script>alert(document.cookie);</script>';

    if(http_vuln_check(port:bcrmPort, url:url,
                       pattern:"><script>alert\(document\.cookie\);</script>",
                       check_header:TRUE,
                       extra_check:">BrowserCRM<"))
    {
      security_message(port:bcrmPort);
      exit(0);
    }
  }
}

exit(99);
