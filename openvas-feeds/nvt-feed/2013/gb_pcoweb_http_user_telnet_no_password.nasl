# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103716");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-05-23 11:24:55 +0200 (Thu, 23 May 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("CAREL pCOWeb 'http' User No Password (Telnet)");

  # nb: User login try could be already seen as an attack
  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "os_detection.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/carel/pcoweb/detected", "Host/runs_unixoide");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote CAREL pCOWeb based device is using no password for
  the 'http' account.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to login via Telnet as user 'http'
  with no password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Login with telnet and set a password or change the shell from
  '/bin/bash' to '/bin/nologin'.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121716/CAREL-pCOWeb-1.5.0-Default-Credential-Shell-Access.html");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

# nb: Don't exit via islocalhost() or is_private_lan() here as such a system should be definitely
# access protected.

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 23);

banner = telnet_get_banner(port: port);

if (!banner || !egrep(string: banner, pattern: "pCOWeb[^ ]* login:", icase: FALSE))
  exit(0);

if (!soc = open_sock_tcp(port))
  exit(0);

buf = telnet_negotiate(socket: soc);
if (!buf || !egrep(string: buf, pattern: "pCOWeb[^ ]* login:", icase: FALSE)) {
  close(soc);
  exit(0);
}

username = "http";

send(socket: soc, data: username + '\r\n');
recv = recv(socket: soc, length: 4096);
if (!recv || "Password:" >< recv) {
  close(soc);
  exit(0);
}

if (recv !~ "\[http@pCOWeb.*/\]\$" && recv !~ "Executing profile.+/s?bin") {
  close(soc);
  exit(0);
}

files = traversal_files("linux");

foreach pattern(keys(files)) {
  file = files[pattern];

  send(socket: soc, data: "cat /" + file + '\r\n');
  recv = recv(socket: soc, length: 8192);

  if (recv && egrep(string: recv, pattern: pattern)) {
    telnet_close_socket(socket: soc, data: recv);
    report = 'It was possible to login as "' + username +
             '" with no password and to execute the command "cat /' + file + '".\n\nResult:\n\n' + recv;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
