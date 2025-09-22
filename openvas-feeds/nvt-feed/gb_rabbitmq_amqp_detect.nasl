# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106498");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-01-06 16:52:19 +0700 (Fri, 06 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RabbitMQ Server Detection (AMPQ)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_amqp_detect.nasl");
  script_require_ports("Services/amqp", 5672);
  script_mandatory_keys("amqp/detected");

  script_tag(name:"summary", value:"Advanced Message Queuing Protocol (AMQP) based detection of
  RabbitMQ Server.");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default: 5672, proto: "amqp");

if (!soc = open_sock_tcp(port))
  exit(0);

req = raw_string("AMQP", 0, 0, 9, 1); # nb: We will use version 9.1 as we don't want to use SASL even if available
send( socket:soc, data:req );
res = recv(socket: soc, min: 8, length: 1024);
close(soc);

res = bin2string(ddata: res, noprint_replacement: " ");

# nb: On RabbitMQ 4.x with SASL enabled the request above only returns "AMQP"
if (ereg(pattern: "productS\s*RabbitMQ", string: res)) {
  version = "unknown";

  vers = eregmatch(pattern: "versionS\s*([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "rabbitmq/detected", value: TRUE);
  set_kb_item(name: "rabbitmq/amqp/detected", value: TRUE);
  set_kb_item(name: "rabbitmq/amqp/port", value: port);
  set_kb_item(name: "rabbitmq/amqp/" + port + "/version", value: version);
  set_kb_item(name: "rabbitmq/amqp/" + port + "/concluded", value: res);
}

exit(0);
