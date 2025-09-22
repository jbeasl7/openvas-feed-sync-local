# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:tandberg:device";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103695");
  script_version("2025-03-21T15:40:43+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-04-10 12:01:48 +0100 (Wed, 10 Apr 2013)");
  script_name("Tandberg Devices Default Credentials (Telnet)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_tandberg_devices_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("tandberg/device/telnet/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Tandberg device has the default password 'TANDBERG'
  set.");

  script_tag(name:"vuldetect", value:"Ttries to login via Telnet with known default credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"telnet"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

res = telnet_negotiate(socket:soc);
if(!res) {
  close(soc);
  exit(0);
}

if("Password:" >!< res) {
  telnet_close_socket(socket:soc, data:res);
  exit(0);
}

send(socket:soc, data:'TANDBERG\n');
res = recv(socket:soc, length:512);
if(!res) {
  close(soc);
  exit(0);
}

if("OK" >!< res) {
  telnet_close_socket(socket:soc, data:res);
  exit(0);
}

cmd = "ifconfig";
send(socket:soc, data:cmd + '\n');
res = recv(socket:soc, length:512);

# nb: No need to call telnet_close_socket() here.
send(socket:soc, data:'exit\n');
close(soc);

if("HWaddr" >< res && "Inet addr" >< res) {
  report = 'Result to the "' + cmd + '" command:\n\n' + chomp(res);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
