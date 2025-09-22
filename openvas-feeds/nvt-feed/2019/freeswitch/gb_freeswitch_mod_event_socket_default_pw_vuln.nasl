# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143230");
  script_version("2024-01-17T06:33:34+0000");
  script_tag(name:"last_modification", value:"2024-01-17 06:33:34 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"creation_date", value:"2019-12-05 09:10:43 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 20:03:00 +0000 (Mon, 16 Dec 2019)");

  script_cve_id("CVE-2019-19492");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("FreeSWITCH Default Password (mod_event_socket)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_freeswitch_mod_event_socket_service_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/mod_event_socket", 8021);
  script_mandatory_keys("freeswitch/mod_event_socket/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"FreeSWITCH is using a known default password in the
  mod_event_socket component.");

  script_tag(name:"vuldetect", value:"Tries to authenticate and checks the response.");

  script_tag(name:"impact", value:"An attacker can use this password to e.g. execute commands via
  the sytstem API to compromise the host.");

  script_tag(name:"solution", value:"Change the default password in event_socket.conf.xml.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/47698");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default: 8021, proto: "mod_event_socket");

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

password = "ClueCon";
data = "auth " + password + '\n\n';

recv = recv(socket: soc, length: 512);
if (recv !~ "^Content-Type\s*:\s*auth/request") {
  close(soc);
  exit(99);
}

send(socket: soc, data: data);
recv = recv(socket: soc, length: 512);
close(soc);

if (recv !~ "Content-Type\s*:\s*command/reply")
  exit(0);

if ("Reply-Text: +OK accepted" >< recv) {
  report = "It was possible to authenticate with the default password '" + password + "'.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
