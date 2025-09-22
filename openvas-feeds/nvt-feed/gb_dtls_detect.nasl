# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145817");
  script_version("2024-03-08T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-03-08 05:05:30 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"creation_date", value:"2021-04-23 05:11:18 +0000 (Fri, 23 Apr 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Datagram Transport Layer Security (DTLS) Protocol Detection");

  script_tag(name:"summary", value:"Detection of services supporting the Datagram Transport Layer
  Security (DTLS) protocol.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Service detection");
  script_dependencies("global_settings.nasl", "gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 443, 601, 853, 2221, 3391, 3478, 4433, 4740, 4755, 5061, 5246, 5247, 5349, 5684, 5868, 6514, 6636, 6699, 8232, 10161, 10162, 41230);

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("ssl_funcs.inc");
include("dtls_func.inc");

# see e.g.: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=dtls+udp
default_ports = make_list(443,            # Cisco/F5 VPN, Citrix Netscaler Gateway
                          601,            # Syslog
                          853,            # DNS query-response protocol run over DTLS or QUIC
                          2221,           # EtherNet/IP over DTLS
                          3391,           # Microsoft Remote Desktop Gateway (RDG)
                          3478,           # STUN
                          4433,           # F5 Network Access VPN
                          4740,           # ipfix protocol over DTLS
                          4755,           # GRE-in-UDP Encapsulation with DTLS
                          5061,           # SIP
                          5246,           # CAPWAP
                          5247,           # CAPWAP
                          5349,           # STUN over DTLS and TURN over DTLS
                          5684,           # DTLS-secured CoAP
                          5868,           # Diameter
                          6514,           # syslog over DTLS
                          6636,           # Encapsulate MPLS packets in UDP tunnels with DTLS
                          6699,           # Babel Routing Protocol over DTLS
                          8232,           # HNCP over DTLS
                          10161,          # SNMP-DTLS
                          10162,          # SNMP-Trap-DTLS
                          41230);         # Z-Wave Protocol over DTLS

port_list = unknownservice_get_ports(default_port_list: default_ports, ipproto: "udp");

# nb: There was no DTLS 1.1 version
version_list = make_list("DTLS10", "DTLS12", "DTLS13");

foreach port (port_list) {

  DTLS_10 = FALSE;
  DTLS_12 = FALSE;
  DTLS_13 = FALSE;
  DTLS_alert_received = FALSE;
  report = "";

  foreach version (version_list) {
    if (!get_udp_port_state(port))
      continue;

    if (service_is_known(port: port, ipproto: "udp"))
      continue;

    if (!soc = open_sock_udp(port))
      continue;

    ret = dtls_client_hello(socket: soc, version: version);
    if (isnull(ret)) {
      close(soc);
      continue;
    }

    seq_num = ret[1];

    recv = ret[0];
    if (strlen(recv) > 27) {
      if (hexstr(recv[25]) == "fe" && hexstr(recv[26]) == "ff") {
        DTLS_10 = TRUE;
      # n.b. restricting this check to only for DTLS12 when we use DTLS12 as DTLS13 negotiates
      # the version info via an extension but still uses DTLS12 in the header like previous versions.
      } else if (hexstr(recv[25]) == "fe" && hexstr(recv[26]) == "fd" && version == "DTLS12") {
        DTLS_12 = TRUE;
      }
    }

    if (version == "DTLS13") {
      # nb: Check if complete Header and Body until extensions have been received
      if (strlen(recv) > 64) {
        # Parse the extension list
        current_pos = 63;
        extension_list_length = ord(recv[current_pos]) * 256 + ord(recv[current_pos + 1]);
        current_pos += 2;
        extension_type = ord(recv[current_pos]) * 256 + ord(recv[current_pos + 1]);
        current_pos += 2;

        # nb: Check until supported_versions extension (0x2b) is found
        while (extension_type != 43) {
          extension_length = ord(recv[current_pos]) * 256 + ord(recv[current_pos + 1]);
          current_pos += 2 + extension_length;
          extension_type = ord(recv[current_pos]) * 256 + ord(recv[current_pos + 1]);
        }

        extension_length = ord(recv[current_pos]) * 256 + ord(recv[current_pos + 1]);
        current_pos += 2;
        for (i = 0; i < extension_length; i += 2) {
          if (hexstr(recv[current_pos]) == "fe" && hexstr(recv[current_pos + 1]) == "fc") {
            DTLS_13 = TRUE;
          }
          current_pos += 2;
        }
      }
    }

    if (seq_num != -1)
      dtls_send_alert(socket: soc, seq_num: seq_num, version: version);

    if (seq_num == -1) {
      DTLS_alert_received = TRUE;
    }

    close(soc);
  }

  if (DTLS_10 || DTLS_12 || DTLS_13) {
    sup_dtls = "";
    set_kb_item(name: "dtls/" + port + "/detected", value: TRUE);
    set_kb_item(name: "dtls/detected", value: TRUE);

    service_register(port: port, proto: "dtls", ipproto: "udp");

    report = 'A DTLS enabled service is running at this port. \n\nThe following DTLS versions are supported:\n';

    if (DTLS_10) {
      report += '-DTLS 1.0\n';
      sup_dtls += "DTLSv1.0;";
    }

    if (DTLS_12) {
      report += '-DTLS 1.2\n';
      sup_dtls += "DTLSv1.2;";
    }

    if (DTLS_13) {
      report += '-DTLS 1.3\n';
      sup_dtls += "DTLSv1.3;";
    }

    set_kb_item(name: "dtls/" + port + "/supported", value: sup_dtls);

    if (DTLS_alert_received) {
      report += '\n\nThe server responded with an "Alert" Message';
      set_kb_item(name: "dtls/" + port + "/alert_received", value: TRUE);
    }

    # Store link between this and gb_dtlsv10_detect.nasl
    # nb: We don't use the host_details.inc functions in both so we need to call this directly.
    register_host_detail(name: "detected_at", value: port + "/udp");

    log_message(port: port, data: chomp(report), proto: "udp");
  }
}

exit(0);
