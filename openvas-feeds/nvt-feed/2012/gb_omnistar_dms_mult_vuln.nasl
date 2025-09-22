# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802467");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-10-11 13:29:47 +0530 (Thu, 11 Oct 2012)");
  script_name("Omnistar Document Manager Software Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Oct/65");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/524380");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"- Multiple sql bugs are located in index.php file with the bound
  vulnerable report_id, delete_id, add_id, return_to, interface, page and sort_order
  parameter requests.

  - The LFI bug is located in the index module with the bound vulnerable 'area'
  parameter request.

  - Multiple non stored XSS bugs are located in the interface exception-handling
  module of the application with the client side  bound vulnerable interface,
  act, name and alert_msg parameter requests.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Omnistar Document Manager Software is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to compromise
  dbms via sql injection or information disclosure via local system file include
  and hijack administrator/moderator/customer sessions via persistent malicious
  script code inject on application side");

  script_tag(name:"affected", value:"Omnistar Document Manager Version 8.0 and prior");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:443);

if(!http_can_host_php(port:port)){
 exit(0);
}

foreach dir (make_list_unique("/", "/dm", "/dms", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(res && ">Document Management Software<" >< res)
  {
    url = dir + "/index.php?interface=><script>alert(document.cookie)"+
                ";</script>";

    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && res && "><script>alert(document.cookie);</script>" >< res &&
       ">Interface Name:<" >< res){
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
