# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149481");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"creation_date", value:"2023-04-03 06:16:33 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Service Location Protocol (SLP) Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 427);

  script_tag(name:"summary", value:"TCP based detection of services supporting the Service Location
  Protocol (SLP).");

  script_xref(name:"URL", value:"https://www.ietf.org/rfc/rfc2608.html");
  script_xref(name:"URL", value:"http://www.openslp.org/");

  exit(0);
}

include("byte_func.inc");
include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("slp_func.inc");

debug = FALSE;

port = unknownservice_get_port(default: 427);

if (!soc = open_sock_tcp(port))
  exit(0);

req_xid = rand() % 0xffff; # nb: Limiting the XID a little...

# TBD: We might want to check for a "service:directory-agent" here as well in the future
msg_exts = make_array("service_type_list", "service:service-agent",
                      "scope_list", "default",
                      "lang_tag", "en");

service_request = slp_create_message(func_id: SLP_MESSAGES_RAW["SrvRqst"], msg_exts: msg_exts, xid: req_xid, debug: debug);
if (isnull(service_request)) {
  close(soc);
  exit(0);
}

send(socket: soc, data: service_request);
recv = recv(socket: soc, length: 512);

if (!recv) {
  close(soc);
  exit(0);
}

# nb: The function has already some basic response checks like an sufficient length of the response
# or to check if the only supported version 2 was returned...
if (!infos = slp_parse_response(data: recv, debug: debug)) {
  close(soc);
  exit(0);
}

# Usually a system is responding with an "SAAdvert (SA Advertisement)" and an XID matching our sent
# XID. But some systems (Directory Agents?) are also responding with one of these combinations:
# - SAAdvert (SA Advertisement) and an XID of 0
# - SrvRply (Service Reply) and an XID matching our sent XID
# which we still want to detect and report such systems here thus these known cases are covered.
res_xid = infos["xid"];

# nb: res_xid is an int and we need to check this as otherwise NULL (type: undef) would be also matched
if (req_xid != res_xid && (typeof(res_xid) != "int" || res_xid != 0)) {
  if (debug) display("DEBUG: Received XID '" + res_xid + "' doesn't match expected XID '" + req_xid + "' or '0'.");
  close(soc);
  exit(0);
}

res_func = infos["func_id_string"];
if (res_func != "SAAdvert (SA Advertisement)" && res_func != "SrvRply (Service Reply)") {
  if (debug) display("DEBUG: Received Function-ID '" + res_func + "' doesn't match expected Function-ID 'SAAdvert (SA Advertisement)' or 'SrvRply (Service Reply)'.");
  close(soc);
  exit(0);
}

req_xid++;

service_type_request = slp_create_message(func_id: SLP_MESSAGES_RAW["SrvTypeRqst"], xid: req_xid, debug: debug);
if (!isnull(service_type_request)) {
  send(socket: soc, data: service_type_request);
  srv_type_recv = recv(socket: soc, length: 512);

  if (srv_type_recv) {
    if (infos = slp_parse_response(data: srv_type_recv, debug: debug)) {
      if (service_type_list = infos["service_type_list"]) {
        set_kb_item(name: "slp/udp/" + port + "/service_type_list", value: service_type_list);
      }
    }
  }
}

close(soc);

set_kb_item(name: "slp/detected", value: TRUE);
set_kb_item(name: "slp/tcp/detected", value: TRUE);
set_kb_item(name: "slp/tcp_or_udp/detected", value: TRUE);
set_kb_item(name: "slp/tcp/" + port + "/detected", value: TRUE);

service_register(port: port, proto: "slp");

# nb:
# - We can register a more generic CPE for the protocol itself which can be used for e.g.:
#   - CVE scans / the CVE scanner
#   - storing the reference from this one to some VTs like e.g. gb_slp_service_wan_access.nasl using
#     the info collected here to show a cross-reference within the reports
# - If changing the syntax of e.g. the "location" below make sure to update VTs like e.g. the
#   gb_slp_service_wan_access.nasl accordingly
register_product(cpe: "cpe:/a:service_location_protocol_project:service_location_protocol", location: port + "/tcp", port: port, proto: "tcp", service: "slp");

# TBD: In the future we could also use the parsed/returned data from slp_parse_response() here...
report = 'A service supporting the Service Location Protocol (SLP) is running at this port.\n\nResponse:\n\n' +
         bin2string(ddata: recv, noprint_replacement: " ");

if (service_type_list)
  report += '\n\nThe following Service Types are published:\n' + service_type_list;

log_message(port: port, data: chomp(report));

exit(0);
