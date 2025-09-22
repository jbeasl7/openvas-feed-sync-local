# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800738");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4680", "CVE-2009-4681");
  script_name("phpDirectorySource Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35941");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35760");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9226");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed to 'search.php' through 'st' parameter is not properly
  sanitised before being returned to the user and before being used in SQL queries.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"phpDirectorySource is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  execute arbitrary SQL commands in the context of an affected site.");

  script_tag(name:"affected", value:"phpDirectorySource version 1.x");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/pds", "/" , http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if("phpDirectorySource" >< res)  {
    req = http_get(item:string(dir, '/search.php?sa=site&sk=a&nl=11&st=">'+
            '<script>alert("', vt_strings["lowercase"], '");</script>'), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if((res =~ "^HTTP/1\.[01] 200" && vt_strings["lowercase"] >< res)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
