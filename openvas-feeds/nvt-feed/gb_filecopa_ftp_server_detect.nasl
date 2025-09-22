# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801124");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FileCopa FTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/intervations/filecopa/detected");

  script_tag(name:"summary", value:"Detection of FileCopa FTP Server.

  This script detects the installed version of FileCopa FTP Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

if(banner && "FileCOPA FTP Server" >< banner){

  version = "unknown";

  filecopeVer = eregmatch(pattern: "FileCOPA FTP Server Version ([0-9.]+)", string: banner);
  if(!isnull(filecopeVer[1])) {
    version = filecopeVer[1];
    set_kb_item(name: "FileCOPA-FTP-Server/Ver", value: version);
  }

  set_kb_item(name: "FileCOPA-FTP-Server/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:filecopa-ftpserver:ftp_server:");
  if (!cpe)
    cpe = 'cpe:/a:filecopa-ftpserver:ftp_server';

  register_product(cpe: cpe, location: port + '/tcp', port: port, service: "ftp");

  log_message(data: build_detection_report(app: "FileCOPA FTP Server", version: version, install: port,
                                           cpe: cpe, concluded: banner),
              port: port);
}

exit(0);
