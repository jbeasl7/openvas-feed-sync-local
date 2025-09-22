# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140512");
  script_version("2023-09-19T05:06:03+0000");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:03 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-11-20 16:46:39 +0700 (Mon, 20 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Factory Interface Network Service (FINS) Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(9600);

  script_tag(name:"summary", value:"TCP based detection of services supporting the Factory Interface
  Network Service (FINS) protocol.");

  script_tag(name:"insight", value:"FINS is a network protocol used by Omron PLCs. The FINS
  communications service was developed by Omron to provide a consistent way for PLCs and computers
  on various networks to communicate.");

  script_xref(name:"URL", value:"http://www.omron.com/");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");

# based on https://github.com/digitalbond/Redpoint/blob/master/omrontcp-info.nse

port = 9600;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

# request address command
req_addr = raw_string(0x46, 0x49, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x0c,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00);

# Parts for the read controller data command
ctrl_data_read1 = raw_string(0x46, 0x49, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00,
                            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x02, 0x00);
ctrl_data_read2 = raw_string( 0x00, 0x00, 0x00, 0xef, 0x05, 0x05, 0x01, 0x00);

# request an address
send(socket: soc, data: req_addr);
recv = recv(socket: soc, length: 512);

if (!recv || recv !~ "^FINS" || strlen(recv) < 24) {
  close(soc);
  exit(0);
}

addr = recv[23];
ctrl_data_read = ctrl_data_read1 + addr + ctrl_data_read2;

# request the controller data
send(socket: soc, data: ctrl_data_read);
recv = recv(socket: soc, length: 512);
close(soc);

if (recv && recv =~ "^FINS" && strlen(recv) >= 65) {
  # Some more information could be extracted (memory card type, program area size, etc) but this doesn't really
  # add some valuable info for vulnerability scanning.
  model = bin2string(ddata: substr(recv, 30, 59), noprint_replacement: '');
  set_kb_item(name: "fins/model", value: model);
  version = bin2string(ddata: substr(recv, 60, 64), noprint_replacement: '');
  set_kb_item(name: "fins/version", value: version);
}

set_kb_item(name: "fins/detected", value: TRUE);

service_register(port: port, proto: "fins", ipproto: "tcp");

report = "A FINS service is running at this port.";

if (model || version) {
  report += '\n\nThe following information was extracted:\n\n' +
            "Controller Model:      " + model + '\n' +
            "Controller Version:    " + version;
}

log_message(port: port, data: report);

exit(0);
