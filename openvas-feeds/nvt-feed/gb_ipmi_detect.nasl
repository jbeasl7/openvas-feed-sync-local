# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103835");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-11-26 11:39:47 +0100 (Tue, 26 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Intelligent Platform Management Interface (IPMI) Detection (IPMI Protocol)");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_require_udp_ports(623);

  script_tag(name:"summary", value:"Detection of services supporting the Intelligent Platform
  Management Interface (IPMI).");

  script_tag(name:"insight", value:"The IPMI is a standardized computer system interface used by
  system administrators for out-of-band management of computer systems and monitoring of their
  operation.");

  exit(0);
}

include("host_details.inc");
include("byte_func.inc");
include("port_service_func.inc");

port = 623;
if(!get_udp_port_state(port))
  exit(0);

rmcp = raw_string(0x06, 0x00, 0xff, 0x07); # Remote Management Control Protocol
gcac = raw_string(0x38);                   # Get Channel Authentication Capabilities

header = rmcp + raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00) + gcac;

level = raw_string(0x04); # Administrator

ipmi_20 = header + raw_string(0x8e) + level + raw_string(0xb5);
ipmi_15 = header + raw_string(0x0e) + level + raw_string(0x35);

reqs = make_list(ipmi_20, ipmi_15);

foreach req(reqs) {

  if(!soc = open_sock_udp(port))
    continue;

  send(socket:soc, data:req);
  recv = recv(socket:soc, length:128);
  close(soc);

  if(!recv || hexstr(recv) !~ "0600ff07" || strlen(recv) < 24 || ord(recv[20]) != 0)
    continue;

  auth_support = dec2bin(dec:ord(recv[22]));

  if(auth_support) {

    if(auth_support[7] == 1) {
      set_kb_item(name:"ipmi/no_auth_supported", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/no_auth_supported", value:TRUE);
    }

    if(auth_support[6] == 1) {
      set_kb_item(name:"ipmi/md2_supported", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/md2_supported", value:TRUE);
    }
  }

  ipmi_version = dec2bin(dec:ord(recv[24]));

  # nb for the register_product() calls:
  # - We can register a more generic CPE for the protocol itself which can be used for e.g.:
  #   - CVE scans / the CVE scanner
  #   - storing the reference from this one to some VTs like e.g.
  #     gb_ipmi_rakp_vuln_jul13_active.nasl using the info collected here to show a cross-reference
  #     within the reports
  # - If changing the syntax of e.g. the "location" below make sure to update VTs like e.g. the
  #   gb_ipmi_rakp_vuln_jul13_active.nasl accordingly

  # nb: Only available if IPMI v2.0 is supported
  if(ipmi_version) {
    if(ipmi_version[7] == 1) { # IPMI Connection Compatibility: 1.5 flag
      set_kb_item(name:"ipmi/version/1.5", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/version/1.5", value:TRUE);
      ipmi_vers_str += "v1.5 ";
      register_product(cpe: "cpe:/a:intel:intelligent_platform_management_interface:1.5", location: port + "/udp", port: port, proto: "udp", service: "ipmi");
    }

    if(ipmi_version[6] == 1) { # IPMI Connection Compatibility: 2.0 flag
      set_kb_item(name:"ipmi/version/2.0", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/version/2.0", value:TRUE);
      ipmi_vers_str += "v2.0";
      register_product(cpe: "cpe:/a:intel:intelligent_platform_management_interface:2.0", location: port + "/udp", port: port, proto: "udp", service: "ipmi");
    }
  } else {
    set_kb_item(name:"ipmi/version/1.5", value:TRUE);
    set_kb_item(name:"ipmi/" + port + "/version/1.5", value:TRUE);
    ipmi_vers_str = "v1.5";
    register_product(cpe: "cpe:/a:intel:intelligent_platform_management_interface:1.5", location: port + "/udp", port: port, proto: "udp", service: "ipmi");
  }

  non_null = dec2bin(dec:ord(recv[23]));

  if(non_null) {

    if(non_null[7] == 1) {
      set_kb_item(name:"ipmi/anonymous_login", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/anonymous_login", value:TRUE);
    }

    if(non_null[6] == 1) {
      set_kb_item(name:"ipmi/null_username", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/null_username", value:TRUE);
    }
  }

  set_kb_item(name:"ipmi/detected", value:TRUE);
  set_kb_item(name:"ipmi/" + port + "/detected", value:TRUE);

  service_register(port:port, ipproto:"udp", proto:"ipmi", message:"An IPMI service is running at this port. Supported IPMI version(s): " + ipmi_vers_str);
  log_message(data:"An IPMI service is running at this port. Supported IPMI version(s): " + ipmi_vers_str, port:port, proto:"udp");

  exit(0);
}

exit(0);
