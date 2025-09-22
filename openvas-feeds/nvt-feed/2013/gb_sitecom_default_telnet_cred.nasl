# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103772");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-08-21 16:02:55 +0200 (Wed, 21 Aug 2013)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sitecom Devices Hard-Coded Credentials (Telnet)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "os_detection.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Sitecom Device is using known hard-coded
  credentials.");

  script_tag(name:"vuldetect", value:"Starts a telnet session with the hard-coded credentials.");

  script_tag(name:"insight", value:"A user can login to the Telnet service (with root privileges)
  using the hard-coded credential admin:1234. This administrative account is hard-coded and cannot
  be changed by a normal user.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain unauthorized access
  to the affected device and perform certain administrative actions.");

  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/sitecom-n300-n600-access-bypass");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 23);

if (get_kb_item("telnet/" + port + "/no_login_banner"))
  exit(0);

if (!soc = open_sock_tcp(port))
  exit(0);

buf = telnet_negotiate(socket: soc);
if ("login:" >!< buf) {
  close(soc);
  exit(0);
}

send(socket: soc, data: 'admin\r\n');
buf = recv(socket: soc, length: 1024);

if ("Password:" >!< buf) {
  close(soc);
  exit(0);
}

send(socket: soc, data: '1234\r\n');
buf = recv(socket: soc, length: 1024);

if ("#" >!< buf) {
  close(soc);
  exit(0);
}

files = traversal_files("linux");

foreach pattern (keys(files)) {
  file = files[pattern];

  send(socket: soc, data: 'cat /' + file + '\r\n');
  buf = recv(socket: soc, length: 1024);

  if (egrep(string: buf, pattern: pattern)) {
    close(soc);
    security_message(data: "The target was found to be vulnerable", port: port);
    exit(0);
  }
}

close(soc);

exit(99);
