# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801518");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3688");
  script_name("NetArtMedia WebSiteAdmin Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=12826");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/398140.php");
  script_xref(name:"URL", value:"http://pridels-team.blogspot.com/2010/09/netartmedia-real-estate-portal-v20-xss.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw exists due to input passed via the 'lng' parameter to
  'ADMIN/login.php' is not properly validating before returning to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NetArtMedia WebSiteAdmin is prone to a directory traversal vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to include and
  execute arbitrary local files via directory traversal sequences in the long parameter.");

  script_tag(name:"affected", value:"NetArtMedia WebSiteAdmin version 2.1");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
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

foreach dir (make_list_unique("/websiteadmin", "/WebSiteAdmin", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">NetArt" >< res && ">WebSiteAdmin<" >< res)
  {
    req = http_get(item:string(dir, '/ADMIN/login.php?lng=../../'), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(': failed to open stream:' >< res && 'No such file or directory' >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
