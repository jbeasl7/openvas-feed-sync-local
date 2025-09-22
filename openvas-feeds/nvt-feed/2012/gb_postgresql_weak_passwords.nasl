# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103552");
  script_version("2024-07-19T15:39:06+0000");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-08-23 14:28:02 +0200 (Thu, 23 Aug 2012)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("PostgreSQL Default Credentials (PostgreSQL Protocol)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_postgresql_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("postgresql/tcp/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"It was possible to login into the remote PostgreSQL as user
  postgres using weak credentials.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");

function check_login(user, password, port) {

  local_var soc, req, len, data, res, typ, code, pass, passlen, salt, x;

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

  if(strlen(res) < len || strlen(res) < 8) {
    close(soc);
    return FALSE;
  }

  typ = substr(res, strlen(res) - 6, strlen(res) - 5);
  typ = ord(typ[1]);

  if(typ != 5) {
    close(soc);
    return FALSE;
  }

  salt = substr(res, strlen(res) - 4);
  userpass = hexstr(MD5(password + user));
  pass = 'md5' + hexstr(MD5(userpass + salt));

  passlen = strlen(pass) + 5;

  req = string(raw_string(0x70), raw_string((passlen >> 24) & 0xff, (passlen >> 16) & 0xff, (passlen >> 8) & 0xff, (passlen) & 0xff), pass, raw_string(0));
  send(socket:soc, data:req);

  res = recv(socket:soc, length:1);

  if(isnull(res) || res[0] != "R") {
    close(soc);
    return FALSE;
  }

  res += recv(socket:soc, length:8);

  if(strlen(res) < 8) {
    close(soc);
    return FALSE;
  }

  code = substr(res,5,strlen(res));

  if(res[0] == "R" && hexstr(code) == "00000000") {

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
  }

  close(soc);
  return FALSE;
}

passwords = make_list("postgres", "", "pgadmin", "admin", "root", "password", "123456", "12345678", "qwerty", "letmein", "database");

if(!port = get_app_port(cpe:CPE, service:"postgresql"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

foreach password(passwords) {

  if(check_login(port:port, user:"postgres", password:password)) {

    data = 'It was possible to login as user postgres';

    if(strlen(password) > 0) {
      data += ' with password "' + password + '".';
    } else {
      data += ' with an empty password.';
    }

    data += '\n\n';

    security_message(port:port, data:data);
    exit(0);
  }
}

exit(99);
