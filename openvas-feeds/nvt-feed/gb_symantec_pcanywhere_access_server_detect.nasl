# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802883");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-09 11:16:49 +0530 (Mon, 09 Jul 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Symantec pcAnywhere Access Server Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 5631);

  script_tag(name:"summary", value:"Detection of Symantec pcAnywhere Access Server.

  The script sends a connection request to the server and attempts to
  extract the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

pcAnyport = unknownservice_get_port( default:5631 );

soc = open_sock_tcp(pcAnyport);
if(!soc){
  exit(0);
}

## Send initial request
initial = raw_string(0x00, 0x00, 0x00, 0x00);
send(socket:soc, data: initial);
pcanydata = recv(socket:soc, length:1024);

close(soc);
sleep(3);

if(!pcanydata){
  exit(0);
}

if("The Symantec pcAnywhere Access Server does not support" >< pcanydata ||
   "Please press <Enter>..." >< pcanydata ||
   "1b593200010342000001001" >< hexstr(pcanydata))
{
  set_kb_item(name:"Symantec/pcAnywhere-server/Installed", value:TRUE);

  cpe = 'cpe:/a:symantec:pcanywhere';

  service_register(port: pcAnyport, ipproto:"tcp", proto:"pcanywheredata");
  register_product(cpe:cpe, location: pcAnyport + '/tcp', port: pcAnyport);
  log_message(data: build_detection_report(app:"Symantec pcAnywhere Access Server",
                    version: "Unknown", install: pcAnyport + '/tcp', cpe:cpe,
                    concluded: "Unknown"), port: pcAnyport);
  exit(0);
}
