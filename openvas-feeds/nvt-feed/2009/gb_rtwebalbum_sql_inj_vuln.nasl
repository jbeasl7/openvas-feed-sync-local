# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900373");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1910");
  script_name("RTWebalbum SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34888");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50406");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to manipulate SQL queries by
  injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"RTWebalbum versions prior to 1.0.574");

  script_tag(name:"insight", value:"Input passed to the 'AlbumId' parameter in index.php is not properly sanitised
  before being used in SQL queries");

  script_tag(name:"solution", value:"Upgrade to RTWebalbum version 1.0.574.");

  script_tag(name:"summary", value:"RTWebalbum is prone to an SQL Injection vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

rtwebPort = http_get_port(default:80);

if(!http_can_host_php(port:rtwebPort)){
  exit(0);
}

foreach rtwebDir (make_list_unique("/rtwebalbum", http_cgi_dirs(port:rtwebPort)))
{

  if(rtwebDir == "/") rtwebDir = "";

  rcvRes = http_get_cache(item: rtwebDir + "/admin.php", port:rtwebPort);

  if("rtwebalbum" >!< rcvRes)
  {
    rcvRes = http_get_cache(item: rtwebDir + "/index.php", port:rtwebPort);
  }

  if(egrep(pattern:"<a\ href=?[^?]+:\/\/sourceforge.net\/projects\/rtwebalbum",
     string:rcvRes) && egrep(pattern:"^HTTP/1\.[01] 200", string:rcvRes))
  {
    # Attack for SQL Injection with AlbumID is 1
    sndReq = http_get(item: rtwebDir + "/index.php?AlbumId=1+AND+1=1#",
                      port:rtwebPort);
    rcvRes = http_keepalive_send_recv(port:rtwebPort, data:sndReq);

    #Exploit for 'True' Condition
    if(rcvRes =~ "<div\ id=.?descrp.?>[^<]" ||
       rcvRes =~ "<div\ id=.?descrp2.?>[^<]")
    {
      security_message(port:rtwebPort, data:"The target host was found to be vulnerable.");
      exit(0);
    }
  }
}

exit(99);
