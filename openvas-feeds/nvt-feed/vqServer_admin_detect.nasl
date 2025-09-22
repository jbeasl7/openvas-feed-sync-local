# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10354");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("vqServer administrative port");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("gb_vqserver_detect.nasl");
  script_mandatory_keys("vqserver/detected");

  script_tag(name:"summary", value:"vqSoft's vqServer administrative port is open.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:9090, proto:"vqServer-admin");
banner = http_get_cache( item:"/", port:port );

if( "Server: vqServer" >< banner && "WWW-Authenticate: Basic realm=/" >< banner ) {
  res = strstr(banner, "Server: ");
  sub = strstr(res, string("\n"));
  res = res - sub;
  res = res - "Server: ";
  res = res - "\n";

  banner = string("vqServer version is : ");
  banner = banner + res;
  log_message(port:port, data:banner);
}

exit( 0 );
