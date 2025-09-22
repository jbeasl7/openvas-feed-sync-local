# SPDX-FileCopyrightText: 2001 HD Moore / Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10826");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Unprotected Netware Management Portal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 HD Moore / Digital Defense Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8008);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable this service if it is not in use or block connections to
  this server on TCP ports 8008 and 8009.");

  script_tag(name:"summary", value:"The Netware Management Portal software is running on this machine.");

  script_tag(name:"impact", value:"The Portal allows anyone to view the current server configuration and
  locate other Portal servers on the network. It is possible to browse the server's filesystem by requesting
  the volume in the URL. However, a valid user account is needed to do so.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8008); #nb: ssl version sometimes on port 8009

res = http_get_cache(item:"/", port:port);
if(res && "NetWare Server" >< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
