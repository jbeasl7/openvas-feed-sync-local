# SPDX-FileCopyrightText: 2002 Andrew Hintz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11193");
  script_version("2024-05-03T15:38:41+0000");
  script_tag(name:"last_modification", value:"2024-05-03 15:38:41 +0000 (Fri, 03 May 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-2243", "CVE-2002-2244", "CVE-2002-2274");
  script_name("akfingerd <= 0.5 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO); # nb: This script should not disrupt the machine at all
  script_copyright("Copyright (C) 2002 Andrew Hintz");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/finger", 79);

  script_xref(name:"URL", value:"https://web.archive.org/web/20210208004126/http://www.securityfocus.com/bid/6323/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208004126/http://www.securityfocus.com/bid/6324/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208004126/http://www.securityfocus.com/bid/6325/");

  script_tag(name:"summary", value:"The remote finger service appears to be vulnerable to a remote
  attack which can disrupt the service of the finger daemon.

  This denial of service does not effect other services that may be running on the remote computer,
  only the finger service can be disrupted.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted finger requests and checks the
  responses.");

  script_tag(name:"insight", value:"akfingerd version 0.5 or earlier is running on the remote host.
  This daemon has a history of security problems, make sure that you are running the latest version
  of akfingerd.

  Versions 0.5 and earlier of akfingerd are vulnerable to a remote denial of service attack. They
  are also vulnerable to several local attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:79, proto:"finger");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

vtstrings = get_vt_strings();

buf = string(vtstrings["default"], "@127.0.0.1@127.0.0.1\r\n"); #send request for forwarded finger query
send(socket:soc, data:buf);
data = recv(socket:soc, length:96);
close(soc);

if("Forwarding is not supported." >< data) { # check for forwarding-denial message used by akfingerd
  soc1 = open_sock_tcp(port); #start a connection and leave it open
  if(soc1) {
    soc2 = open_sock_tcp(port); #start another connection and issue a request on it
    if(soc2) {
      send(socket:soc2, data:buf);
      data2 = recv(socket:soc2, length:96);
      if(!data2)
        security_message(port:port); #akfingerd won't send a reply on second connection while the first is still open
      close(soc2);
    }
    else
      security_message(port:port);
    close(soc1);
  }
}

exit(0);
