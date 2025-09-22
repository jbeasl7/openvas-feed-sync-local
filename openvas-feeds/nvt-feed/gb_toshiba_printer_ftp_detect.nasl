# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142904");
  script_version("2024-06-21T15:40:03+0000");
  script_tag(name:"last_modification", value:"2024-06-21 15:40:03 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-09-18 02:35:46 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (FTP)");

  script_tag(name:"summary", value:"FTP based detection of Toshiba printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/toshiba/printer/detected");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

# 220 ET0021B7F5158A TOSHIBA e-STUDIO306CS FTP Server NH6.GM.N632 ready.
# 220 ET0021B7F5864C TOSHIBA e-STUDIO305CS FTP Server NH7.GM.N205 ready.
# Note: NHxx.xx.xxx is the network version and not the firmware version
if (banner && "TOSHIBA " >< banner && " FTP Server" >< banner) {
  set_kb_item(name: "toshiba/printer/detected", value: TRUE);
  set_kb_item(name: "toshiba/printer/ftp/detected", value: TRUE);
  set_kb_item(name: "toshiba/printer/ftp/port", value: port);
  set_kb_item(name: "toshiba/printer/ftp/" + port + "/concluded", value: banner);

  model = eregmatch(pattern: "TOSHIBA ([^ ]+) FTP", string: banner);
  if (!isnull(model[1]))
    set_kb_item(name: "toshiba/printer/ftp/" + port + "/model", value: model[1]);
}

exit(0);
