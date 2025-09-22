# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106522");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-26 10:19:28 +0700 (Thu, 26 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Modbus Detection");

  script_tag(name:"summary", value:"A Modbus Service is running at this host.

  Modbus is a serial communications protocol for use with programmable logic controllers (PLCs).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "nessus_detect.nasl"); # nessus_detect.nasl to avoid double check for echo tests.
  script_require_ports("Services/unknown", 502, 503);

  script_xref(name:"URL", value:"http://www.modbus.org/");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port(default: 502);

# nb: Set by nessus_detect.nasl if we have hit a service which echos everything back
if (get_kb_item("generic_echo_test/" + port + "/failed"))
  exit(0);

# nb: Set by nessus_detect.nasl as well. We don't need to do the same test multiple times...
if (!get_kb_item("generic_echo_test/" + port + "/tested")) {
  soc = open_sock_tcp(port);
  if (!soc)
    exit(0);

  send(socket: soc, data: "TestThis\r\n");
  r = recv_line(socket: soc, length: 10);
  close(soc);
  # We don't want to be fooled by echo & the likes
  if ("TestThis" >< r) {
    set_kb_item(name: "generic_echo_test/" + port + "/failed", value: TRUE);
    exit(0);
  }
}

sock = open_sock_tcp(port);
if (!sock)
  exit(0);

for (i=0; i<3; i++) {

  req_info = raw_string(0x00, 0x00,     # Transport ID
                        0x00, 0x00,     # Protocol ID
                        0x00, 0x05,     # Length
                        i,              # Unit ID (we cycle just through the first 3, until we get a response)
                        0x2B,           # Function Code (Read Device Identification)
                        0x0E,           # MEI Type: (Read Device Identification)
                        0x01,           # Object ID (0x01: Basic, 0x02: Regular, 0x03: Extended)
                                        # some devices do not response properly for regular and extended requests
                        0x00);          # Vendor ID

  send(socket: sock, data: req_info, length:strlen(req_info));
  res = recv(socket:sock, length:1024, timeout:1);

  if (res) {
    # skip 7 bytes of MBAP header
    offset = 7;

    # Handle exception responds
    # Exceptions contain the sent function code + 0x80 (0x2b + 0x80 = 0xab) and the exception code itself as the
    # second byte
    # https://en.wikipedia.org/wiki/Modbus#Exception_responses
    if (strlen(res) == 9) {
      if (hexstr(res[offset]) == "ab") {
        service_register(port: port, ipproto: "tcp", proto: "modbus");

        report = 'A Modbus service is running at this port.';

        log_message(port: port, data: report);

        close(sock);
        exit(0);
      } else {
        close(sock);
        exit(0);
      }
    }

    # we need at least 7 more info bytes
    if (strlen(res) < (7 + offset))
      continue;

    # Response must have the same function code and MEI type
    if (ord(res[0+offset]) != 43 && ord(res[1+offset]) != 14)
      continue;

    num_of_objects = ord(res[6 + offset]);
    data = substr(res, offset + 7);

    start = 0;
    failed = FALSE;

    for (i = 0; i<num_of_objects; i++) {
      if (start + 1 > strlen(data)) {
        failed = TRUE;
        break;
      }

      id = ord(data[start]);
      length = ord(data[start + 1]);
      if (start + 1 + length > strlen(data)) {
        failed = TRUE;
        break;
      }

      value = substr(data, start + 2, start + 1 + length);

      if (id == 0) {
        vendor = chomp(value);
        set_kb_item(name: "modbus/vendor", value: vendor);
      }
      else if (id == 1) {
        prod_code = chomp(value);
        set_kb_item(name: "modbus/prod_code", value: prod_code);
      }
      else if (id == 2) {
        version = chomp(value);
        set_kb_item(name: "modbus/version", value: version);
      }
      else if (id == 3) {
        vendor_url = chomp(value);
      }
      else if (id == 4) {
        prod_name = chomp(value);
        set_kb_item(name: "modbus/prod_name", value: prod_name);
      }
      else if (id == 5) {
        model = chomp(value);
        set_kb_item(name: "modbus/model", value: model);
      }
      else if(id == 6) {
        user_app_name = chomp(value);
        set_kb_item(name: "modbus/user_app_name", value: user_app_name);
      }

      start = start + 2 + length;
    }

    if (failed)
      continue;

    close(sock);

    service_register(port: port, ipproto: "tcp", proto: "modbus");

    report = 'A Modbus service is running at this port.\n\nThe following information was extracted:\n\n' +
             'Vendor Name:           ' + vendor + '\n' +
             'Product Code:          ' + prod_code + '\n' +
             'Software Version:      ' + version + '\n';

    if (vendor_url)
      report += 'Vendor URL:            ' + vendor_url + '\n';
    if (prod_name)
      report += 'Product Name:          ' + prod_name + '\n';
    if (model)
      report += 'Model Name:            ' + model + '\n';
    if (user_app_name)
      report += 'User Application Name: ' + user_app_name + '\n';

    log_message(port: port, data: report);

    exit(0);
  }
}

close(sock);

exit(0);
