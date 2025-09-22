# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11929");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SAP/DB vserver Detection");
  # In fact, the overflow is against niserver (on port 7269)
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(7210);

  script_tag(name:"summary", value:"SAP/DB vserver, an ERP software, is running on the remote port.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("string_hex_func.inc");

port = 7210;
if(!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

req = hex2raw(s:"51000000035b00000100000000000000" +
                "000004005100000000023900040b0000" +
                "d03f0000d03f00000040000070000000" +
                "4e455353555320202020202020202020" +
                "0849323335333300097064626d73727600");

send(socket:soc, data:req);
res = recv(socket:soc, length:64);
close(soc);

if(!res || strlen(res) < 7)
  exit(0);

if(substr(res, 0, 6) == hex2raw(s:"40000000035c00")) {
  log_message(port:port);
  service_register(port:port, proto:"sap_db_vserver");
}

exit(0);
