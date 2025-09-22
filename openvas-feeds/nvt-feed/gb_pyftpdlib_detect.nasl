# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801612");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("pyftpdlib Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/pyftpdlib/detected");

  script_tag(name:"summary", value:"Detection of pyftpdlib

  This script finds the version of running FTPServer.py in pyftpdlib.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);

if(banner && "pyftpd" >< tolower(banner)){

  version = "unknown";

  ver = eregmatch(pattern:"(Pyftpd|pyftpdlib) ([0-9.]+)", string:banner, icase:TRUE);
  if(!isnull(ver[2])) {
    version = ver[2];
    set_kb_item(name:"pyftpdlib/Ver", value:version);
  }

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:g.rodola:pyftpdlib:");
  if (!cpe)
    cpe = 'cpe:/a:g.rodola:pyftpdlib';

  register_product(cpe:cpe, location:port + '/tcp', port:port, service:"ftp");

  log_message(data:build_detection_report(app:"pyftpdlib FTP Server", version:version, install:port + '/tcp',
                                          cpe:cpe, concluded:banner),
              port:port);
}

exit(0);
