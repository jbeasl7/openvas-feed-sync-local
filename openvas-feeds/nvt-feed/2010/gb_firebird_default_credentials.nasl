# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100792");
  script_version("2025-03-21T15:40:43+0000");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-08 15:41:05 +0200 (Wed, 08 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Firebird Default Credentials (Firebird Protocol)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("firebird_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/gds_db", 3050);
  script_mandatory_keys("firebird/db/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"It is possible to connect to the remote database service using
  default credentials.");

  script_tag(name:"vuldetect", value:"Tries to connect with default credentials and checks the
  response.");

  script_tag(name:"insight", value:"The remote Firebird Server uses default credentials
  (SYSDBA/masterkey).");

  script_tag(name:"impact", value:"An attacker may use this flaw to execute commands against the
  remote host, as well as read your database content.");

  script_tag(name:"solution", value:"Change the default password by using the gsec management
  tool.");

  script_xref(name:"URL", value:"https://www.firebirdsql.org/manual/qsg2-config.html#qsg2-config-security");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("byte_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default: 3050, proto: "gds_db");

if (!soc = open_sock_tcp(port))
  exit(0);

vt_strings = get_vt_strings();

file = "/" + vt_strings["lowercase"] + ".fdb";
file_length = strlen(file);
if (file_length % 4 != 0)
  file_pad = crap(data: raw_string(0x00), length: 4 - (file_length % 4));

user        = vt_strings["lowercase"];
user_length = strlen(user);
host        = this_host_name();
host_length = strlen(host);
u_h_length  = user_length + host_length;

if ((u_h_length + 2) % 4 != 0)
  u_h_pad = crap(data: raw_string(0x00), length: 4 - ((u_h_length + 2) % 4));

firebird_auth_packet =
  mkdword(1) +              # Opcode: Connect (1)
  mkdword(19) +             # Operation: Attach (19)
  mkdword(2) +              # Version: 2
  mkdword(36) +             # Client Architecture: Linux (36)
  mkdword(file_length) + file + file_pad +
  mkdword(2) +              # Version option count: 2 -> See below
  mkdword(u_h_length + 6) +
  raw_string(0x01) +        # Currently unknown
  raw_string(user_length) + user +
  raw_string(0x04) +        # Currently unknown
  raw_string(host_length) + host +
  raw_string(0x06, 0x00) +  # Currently unknown
  u_h_pad +
  # Preferred version 1
  mkdword(8) +              # Version: 8
  mkdword(1) +              # Architecture: Generic (1)
  mkdword(2) +              # Minimum type: 2
  mkdword(3) +              # Maximum type: 3
  mkdword(2) +              # Preference weight: 2
  # Preferred version 2
  mkdword(10) +             # Version: 10
  mkdword(1)  +             # Architecture: Generic (1)
  mkdword(2)  +             # Minimum type: 2
  mkdword(3)  +             # Maximum type: 3
  mkdword(4);               # Preference weight: 4

send(socket: soc, data: firebird_auth_packet);
res = recv(socket: soc, length: 1024);

if (!isnull(res) && strlen(res) == 16 && "030000000a0000000100000003" >< hexstr(res)) {
  path = "/"; # nb: This is not a valid name so the database is not created.
  path_length = strlen(path);
  path_pad = crap(data: raw_string(0x00), length: ((4 - (strlen(path) % 4))) * (strlen(path) % 4 > 0));

  user = "SYSDBA";
  pass = "masterkey";

  dpd = raw_string(0x01, 0x1c, strlen(user), user, 0x1d, strlen(pass), pass);

  req = mkdword(20) +       # Opcode: Create
        mkdword(0) +
        mkdword(path_length) + path + path_pad +
        mkdword(strlen(dpd)) + dpd;

  req += crap(data: raw_string(0x00), length: ((4 - (strlen(req) % 4))) * (strlen(req) % 4 > 0));

  send(socket: soc, data: req);
  res = recv(socket: soc, length: 1024);
  close(soc);

  if (strlen(res) >= 16 && "CreateFile" >< res) {
    report = "It was possible to authenticate with the following credentials:" +
             '\n\nUsername: "' + user + '", Password: "' + pass + '"';
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0); # Might be protocol version dependent
