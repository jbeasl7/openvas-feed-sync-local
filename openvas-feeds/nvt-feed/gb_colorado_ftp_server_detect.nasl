# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807878");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-23 08:13:26 +0200 (Tue, 23 Aug 2016)");
  script_name("ColoradoFTP Server Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/coldcore/coloradoftp/detected");

  script_tag(name:"summary", value:"Detects the installed version of
  ColoradoFTP Server.

  The script sends a connection request to the server and attempts to
  extract the version from the reply");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);

if(banner && "Welcome to ColoradoFTP" >< banner && "www.coldcore.com" >< banner) {

  ftpVer = "unknown";
  set_kb_item(name:"ColoradoFTP/Server/installed", value:TRUE);
  set_kb_item(name:"ColoradoFTP/Server/Ver", value:ftpVer);

  cpe = "cpe:/a:colorado:coloradoftpserver";
  register_product(cpe:cpe, location:"/", port:ftpPort, service:"ftp");
  log_message(data:build_detection_report(app:"ColoradoFT Server",
                                           version:ftpVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:banner),
                                           port:ftpPort);
}

exit(0);
