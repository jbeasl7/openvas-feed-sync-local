# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801924");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("phpAlbum.net Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://videowarning.com/?p=6499");
  script_xref(name:"URL", value:"http://www.phpdatabase.net/project/issues/402");
  script_xref(name:"URL", value:"http://securityreason.com/wlb_show/WLB-2011040083");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100428/phpalbumdotnet-xssxsrfexec.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could result in a compromise of the
  application, theft of cookie-based authentication credentials, disclosure or
  modification of sensitive data.");

  script_tag(name:"affected", value:"phpAlbum.net version 0.4.1-14_fix06 and prior.");

  script_tag(name:"insight", value:"The flaws are due to

  - Failure in the 'main.php' script to properly verify the source of HTTP request.

  - Failure in the 'phpdatabase.php' script to properly sanitize user-supplied
  input in 'var3' variable.

  - Failure in the 'setup.php' script to properly sanitize user-supplied input
  in 'ar3', 'p_new_group_name' variables.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"phpAlbum.net is prone to Multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/phpAlbum", "/phpAlbumnet", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/main.php", port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  if('<title>phpAlbum.net</title>' >< res)
  {
     req = http_get(item:string(dir, '/main.php?cmd=setup&var1=user&var3=1">' +
                                '<script>alert("XSS-TEST")</script>'), port:port);
     res = http_keepalive_send_recv(port:port, data:req);
     if(res =~ "^HTTP/1\.[01] 200" && '><script>alert("XSS-TEST")</script>' >< res)
     {
       security_message(port:port);
       exit(0);
     }
  }
}

exit(99);
