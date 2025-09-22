# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803773");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2013-2652");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-10-28 15:46:55 +0530 (Mon, 28 Oct 2013)");
  script_name("WebCollab 'item' Parameter HTTP Response Splitting Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTTP
  headers, which will be included in a response sent to the user.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to inject malicious data in header or not.");

  script_tag(name:"insight", value:"Input passed via the 'item' GET parameter to help/help_language.php is not
  properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to WebCollab 3.31 or later.");

  script_tag(name:"summary", value:"WebCollab is prone to HTTP response splitting vulnerability.");

  script_tag(name:"affected", value:"WebCollab versions 3.30 and prior.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55235");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63247");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Oct/119");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123771");
  script_xref(name:"URL", value:"http://freecode.com/projects/webcollab/releases/358621");
  script_xref(name:"URL", value:"http://sourceforge.net/p/webcollab/mailman/message/31536457");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/webcollab-330-http-response-splitting");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/webcollab", "/WebCollab", http_cgi_dirs(port:http_port)))
{
  if(dir == "/") dir = "";

   res = http_get_cache(item:string(dir, "/index.php"),  port: http_port);

   if(res && egrep(pattern:">WebCollab<", string:res))
   {
     url = dir + '/help/help_language.php?item=%0d%0a%20FakeHeader%3a%20' +
           'Fakeheaderis%20injected&amp;lang=en&amp;type=help';

     if(http_vuln_check(port:http_port, url:url, pattern:"FakeHeader: Fakeheaderis injected",
       extra_check:">WebCollab<"))
     {
       security_message(port:http_port);
       exit(0);
     }
  }
}

exit(99);
