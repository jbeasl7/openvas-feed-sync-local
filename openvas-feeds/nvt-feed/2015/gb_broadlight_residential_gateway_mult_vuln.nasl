# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805596");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-26 10:03:52 +0530 (Fri, 26 Jun 2015)");
  script_name("Broadlight Residential Gateway DI3124 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Broadlight Residential Gateway is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read sensitive information or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as no user
  authentication is required for accessing multiple sensitive pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to change DNS and gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Broadlight Residential Gateway DI3124");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37214");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

gatePort = http_get_port(default:80);

rcvRes = http_get_cache(item: "/", port:gatePort);

if(rcvRes && "title>Broadlight Residential Gateway<" >< rcvRes)
{

  url = "/cgi-bin/getconf.cgi";

  sndReq = http_get(item: url, port:gatePort);
  rcvRes = http_keepalive_send_recv(port:gatePort, data:sndReq);

  if(rcvRes =~ "<username>.*</username>" && rcvRes =~ "<password>.*</password>")
  {
    security_message(port:gatePort);
    exit(0);
  }
}
