# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103798");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-10-07 14:28:02 +0200 (Mon, 07 Oct 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("PostgreSQL No Password Protection (PostgreSQL Protocol)");

  # nb: User login try could be already seen as an attack
  script_category(ACT_ATTACK);
  script_family("Databases");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_postgresql_consolidation.nasl", "gb_default_credentials_options.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("postgresql/tcp/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks",
                      "keys/islocalhost", "keys/is_private_lan");

  script_tag(name:"summary", value:"It was possible to login into the remote PostgreSQL as user
  'postgres' without using a password.");

  script_tag(name:"vuldetect", value:"Evaluates if the remote PostgreSQL server is protected by a
  password.

  Notes:

  - No scan result is expected if localhost (127.0.0.1) was scanned (self scanning)

  - If the scanned network is e.g. a private LAN which contains systems not accessible to the public
  (access restricted) and it is accepted that the target host is accessible without a password
  please set the 'Network type' configuration of the following VT to 'Private LAN':

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information.");

  script_tag(name:"solution", value:"Set a password as soon as possible.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

# nb: No point in reporting on self scans via 127.0.0.1 as services are often just bound to just
# 127.0.0.1 and thus not accessible externally...
if (islocalhost())
  exit(0);

include("host_details.inc");
include("network_func.inc");

# nb: This might be acceptable from user side if the system is located within a restricted LAN so
# allow this case via the configuration within global_settings.nasl.
if (is_private_lan())
  exit(0);

function check_login(user, port) {

  local_var soc, req, len, data, res, typ, code, x;

  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  h = raw_string((0x03 >> 8) & 0xFF, 0x03 & 0xFF, (0x00 >> 8) & 0xFF, 0x00 & 0xFF);
  null = raw_string(0);

  req = string(h,
               "user", null, user,
               null,
               "database", null, "postgres",
               null,
               "client_encoding", null, "UNICODE",
               null,
               "DateStyle", null, "ISO",
               null, null);

  len = strlen(req) + 4;
  req = raw_string((len >> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, (len) & 0xff) + req;

  send(socket:soc, data:req);
  res = recv(socket:soc, length:1);
  if (isnull(res) || res[0] != "R") {
    close(soc);
    exit(0);
  }

  res += recv(socket:soc, length:4);
  if (strlen(res) < 5) {
    close(soc);
    exit(0);
  }

  x = substr(res, 1, 4);

  len = ord(x[0]) << 24 | ord(x[1]) << 16 | ord(x[2]) << 8 | ord(x[3]);
  res += recv(socket:soc, length:len);

  if (strlen(res) < len || strlen(res) < 8) {
    close(soc);
    return FALSE;
  }

  typ = substr(res, strlen(res) - 6, strlen(res) - 5);
  typ = ord(typ[1]);

  if (typ != 0) {
    close(soc);
    return FALSE;
  }

  recv(socket:soc, length:65535);

  sql = "select version();";
  sqllen = strlen(sql) + 5;
  slen = raw_string((sqllen >> 24) & 0xff, (sqllen >> 16) & 0xff, (sqllen >> 8) & 0xff, (sqllen) & 0xff);

  req = raw_string(0x51) + slen + sql + raw_string(0x00);
  send(socket:soc, data:req);

  res = recv(socket:soc, length:1);

  if(isnull(res) || res[0] != "T") {
    close(soc);
    return FALSE;
  }

  res += recv(socket:soc, length:1024);

  close(soc);

  if("PostgreSQL" >< res && "SELECT" >< res)
    return TRUE;

  return FALSE;
}

if (!port = get_app_port(cpe:CPE, service:"postgresql"))
  exit(0);

if (!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if (check_login(port:port, user:"postgres")) {
  security_message(port:port);
  exit(0);
}

exit(99);
