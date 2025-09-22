# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100151");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PostgreSQL Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_add_preference(name:"Postgres Username:", value:"postgres", type:"entry", id:1);
  script_add_preference(name:"Postgres Password:", value:"postgres", type:"password", id:2);

  script_tag(name:"summary", value:"TCP based detection of PostgreSQL.");

  script_tag(name:"vuldetect", value:"The script sends a connection request to the server
  (user:postgres, DB:postgres) and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("dump.inc");
include("postgresql.inc");

function check_login(user, password, port) {

  local_var user, password, port;
  local_var soc, req, res, x, len, typ, salt, userpass, pass, passlen;
  local_var code, sql, sqllen, slen, version, vers;
  global_var concluded;

  soc = open_sock_tcp(port);
  if(!soc)
    return;

  req = postgresql_create_startup_packet(user:user, db:"postgres");

  send(socket:soc, data:req);
  res = recv(socket:soc, length:1);
  if(isnull(res) || res[0] != "R") {
    close(soc);
    return;
  }

  res += recv(socket:soc, length:4);
  if(strlen(res) < 5) {
    close(soc);
    return;
  }

  x = substr(res, 1, 4);

  len = ord(x[0]) << 24 | ord(x[1]) << 16 | ord(x[2]) << 8 | ord(x[3]);
  res += recv(socket:soc, length:len);
  if(strlen(res) < len || strlen(res) < 8) {
    close(soc);
    return;
  }

  typ = substr(res, strlen(res) - 6, strlen(res) - 5);
  typ = ord(typ[1]);

  if(typ != 5) {
    close(soc);
    return;
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
    return;
  }

  res += recv(socket:soc, length:8);
  if(strlen(res) < 8) {
    close(soc);
    return;
  }

  code = substr(res, 5, strlen(res));

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
      return;
    }

    res += recv(socket:soc, length:1024);
    close(soc);

    if("PostgreSQL" >< res && "SELECT" >< res) {
      res = bin2string(ddata:res);
      version = eregmatch(pattern:"PostgreSQL (([0-9.]+)([a-z0-9.]+)?)", string:res);

      if(!isnull(version[1]) && isnull(version[3])) {
        vers = version[1];
      } else if(!isnull(version[2]) && !isnull(version[3])) {
        vers = version[2] + "." + version[3];
      }
    }

    if(vers) {
      concluded = "select version(); query result: " + res;
      return vers;
    }
  }

  close(soc);
  return;
}

port = service_get_port(default:5432, proto:"postgresql");

if(!soc = open_sock_tcp(port))
  exit(0);

req = postgresql_create_startup_packet(user:"postgres", db:"postgres");
send(socket:soc, data:req);
res = recv(socket:soc, length:256);
close(soc);

if(!res || res[0] !~ "[ER]")
  exit(0);

dump = bin2string(ddata:res, noprint_replacement:" ");
concluded = chomp(hexdump(ddata:res));
b = substr(res, 1, 4);
blen = ord(b[0]) / 24 | ord(b[1]) / 16 | ord(b[2]) / 8 | ord(b[3]);

# e.g.:
#
# 0x0000:  45 00 00 01 79 53 46 41 54 41 4C 00 43 35 37 4D    E...ySFATAL.C57M
# 0x0010:  30 32 00 4D 74 68 65 20 64 61 74 61 62 61 73 65    02.Mthe database
# 0x0020:  20 73 79 73 74 65 6D 20 69 73 20 69 6E 20 72 65     system is in re
# 0x0030:  63 6F 76 65 72 79 20 6D 6F 64 65 00 44 6C 61 73    covery mode.Dlas
# 0x0040:  74 20 72 65 70 6C 61 79 65 64 20 72 65 63 6F 72    t replayed recor
# 0x0050:  64 20 61 74 20 37 41 2F 38 38 30 30 30 34 42 38    d at 7A/880004B8
# 0x0060:  0A 2D 20 56 45 52 53 49 4F 4E 3A 20 50 6F 73 74    .- VERSION: Post
# 0x0070:  67 72 65 53 51 4C 20 39 2E 34 2E 32 36 20 28 47    greSQL 9.4.26 (G
# 0x0080:  72 65 65 6E 70 6C 75 6D 20 44 61 74 61 62 61 73    reenplum Databas
# 0x0090:  65 20 36 2E 32 35 2E 33 2D 6D 64 62 2B 79 65 7A    e 6.25.3-mdb+yez
# 0x00A0:  7A 65 79 2B 79 61 67 70 63 63 2D 72 2B 64 65 76    zey+yagpcc-r+dev
# 0x00B0:  2E 32 37 2E 67 32 33 63 62 65 30 36 61 33 66 20    .27.g23cbe06a3f  # nb: Space is expected here...
# 0x00C0:  62 75 69 6C 64 20 64 65 76 2D 6F 73 73 29 20 6F    build dev-oss) o
# 0x00D0:  6E 20 78 38 36 5F 36 34 2D 70 63 2D 6C 69 6E 75    n x86_64-pc-linu
# 0x00E0:  78 2D 67 6E 75 2C 20 63 6F 6D 70 69 6C 65 64 20    x-gnu, compiled  # nb: Space is expected here...
# 0x00F0:  62 79 20 67 63 63 2D 36 20 28 55 62 75 6E 74 75    by gcc-6 (Ubuntu
#
# or:
#
# 0x00:  45 00 00 00 94 53 46 41 54 41 4C 00 43 32 38 30    E....SFATAL.C280
# 0x10:  30 30 00 4D 6E 6F 20 70 67 5F 68 62 61 2E 63 6F    00.Mno pg_hba.co
# 0x20:  6E 66 20 65 6E 74 72 79 20 66 6F 72 20 68 6F 73    nf entry for hos
# 0x30:  74 20 22 <redacted>                                t "<redacted>
# 0x40:  22 2C 20 75 73 65 72 20 22 70 6F 73 74 67 72 65    ", user "postgre
# 0x50:  73 22 2C 20 64 61 74 61 62 61 73 65 20 22 70 6F    s", database "po
# 0x60:  73 74 67 72 65 73 22 2C 20 53 53 4C 20 6F 66 66    stgres", SSL off
# 0x70:  00 46 61 75 74 68 2E 63 00 4C 34 37 31 00 52 43    .Fauth.c.L471.RC
# 0x80:  6C 69 65 6E 74 41 75 74 68 65 6E 74 69 63 61 74    lientAuthenticat
# 0x90:  69 6F 6E 00 00                                     ion..
#
if((dump[0] == "E" &&
    ("ERROR"   >< dump ||
     "FATAL"   >< dump ||
     "PANIC"   >< dump ||
     "WARNING" >< dump ||
     "NOTICE"  >< dump ||
     "DEBUG"   >< dump ||
     "INFO"    >< dump ||
     "LOG"     >< dump)
   ) ||

   (dump[0] == "R" &&

     # e.g. (only for the "blen == 12" case):
     #
     # 0x00:  52 00 00 00 0C 00 00 00 05 AA DB BD DD             R............
     #
     # or:
     #
     # 0x00:  52 00 00 00 0C 00 00 00 05 FB 13 4D 38             R..........M8
     #
     # This is returned for the "blen == 8" case):
     #
     # 0x00:  52 00 00 00 08 00 00 00 00 53 00 00 00 18 63 72    R........S....cr
     # 0x10:  61 74 65 5F 76 65 72 73 69 6F 6E 00 33 2E 33 2E    ate_version.3.3.
     # 0x20:  35 00 53 00 00 00 18 73 65 72 76 65 72 5F 76 65    5.S....server_ve
     # 0x30:  72 73 69 6F 6E 00 31 30 2E 35 00 53 00 00 00 19    rsion.10.5.S....
     # 0x40:  73 65 72 76 65 72 5F 65 6E 63 6F 64 69 6E 67 00    server_encoding.
     # 0x50:  55 54 46 38 00 53 00 00 00 19 63 6C 69 65 6E 74    UTF8.S....client
     # 0x60:  5F 65 6E 63 6F 64 69 6E 67 00 55 54 46 38 00 53    _encoding.UTF8.S
     # 0x70:  00 00 00 12 64 61 74 65 73 74 79 6C 65 00 49 53    ....datestyle.IS
     # 0x80:  4F 00 53 00 00 00 11 54 69 6D 65 5A 6F 6E 65 00    O.S....TimeZone.
     # 0x90:  55 54 43 00 53 00 00 00 19 69 6E 74 65 67 65 72    UTC.S....integer
     # 0xA0:  5F 64 61 74 65 74 69 6D 65 73 00 6F 6E 00 5A 00    _datetimes.on.Z.
     # 0xB0:  00 00 05 49                                        ...I
     #
     # or:
     #
     # 0x00:  52 00 00 00 08 00 00 00 00 53 00 00 00 1E 63 6C    R........S....cl
     # 0x10:  69 65 6E 74 5F 65 6E 63 6F 64 69 6E 67 00 53 51    ient_encoding.SQ
     # 0x20:  4C 5F 41 53 43 49 49 00 53 00 00 00 17 44 61 74    L_ASCII.S....Dat
     # 0x30:  65 53 74 79 6C 65 00 49 53 4F 2C 20 4D 44 59 00    eStyle.ISO, MDY.
     # 0x40:  53 00 00 00 14 69 73 5F 73 75 70 65 72 75 73 65    S....is_superuse
     # 0x50:  72 00 6F 6E 00 53 00 00 00 17 73 65 72 76 65 72    r.on.S....server
     # 0x60:  5F 76 65 72 73 69 6F 6E 00 37 2E 34 00 53 00 00    _version.7.4.S..
     # 0x70:  00 23 73 65 73 73 69 6F 6E 5F 61 75 74 68 6F 72    .#session_author
     # 0x80:  69 7A 61 74 69 6F 6E 00 70 6F 73 74 67 72 65 73    ization.postgres
     # 0x90:  00 4B 00 00 00 0C 00 00 36 94 56 F4 8D 68 5A 00    .K......6.V..hZ.
     # 0xA0:  00 00 05 49
     #
     # or:
     #
     # 0x00:  52 00 00 00 08 00 00 00 00 53 00 00 00 1C 63 6C    R........S....cl
     # 0x10:  69 65 6E 74 5F 65 6E 63 6F 64 69 6E 67 00 55 4E    ient_encoding.UN
     # 0x20:  49 43 4F 44 45 00 53 00 00 00 17 73 65 72 76 65    ICODE.S....serve
     # 0x30:  72 5F 76 65 72 73 69 6F 6E 00 39 2E 35 00 53 00    r_version.9.5.S.
     # 0x40:  00 00 19 73 65 72 76 65 72 5F 65 6E 63 6F 64 69    ...server_encodi
     # 0x50:  6E 67 00 55 54 46 38 00 53 00 00 00 12 44 61 74    ng.UTF8.S....Dat
     # 0x60:  65 53 74 79 6C 65 00 49 53 4F 00 53 00 00 00 19    eStyle.ISO.S....
     # 0x70:  69 6E 74 65 67 65 72 5F 64 61 74 65 74 69 6D 65    integer_datetime
     # 0x80:  73 00 6F 6E 00 53 00 00 00 11 54 69 6D 65 5A 6F    s.on.S....TimeZo
     # 0x90:  6E 65 00 55 54 43 00 5A 00 00 00 05 49             ne.UTC.Z....I
     #
     (blen == 8 || blen == 12 ||

     # 0x00:  52 00 00 00 17 00 00 00 0A 53 43 52 41 4D 2D 53    R........SCRAM-S
     # 0x10:  48 41 2D 32 35 36 00 00                            HA-256..
     #
     (blen == 23 && "SCRAM-SHA-256" >< res)
   )
  )) {

  if(dump[0] == "R") {
    version = eregmatch(pattern:"server_version (([0-9.]+)([a-z0-9.]+)?)", string:dump);
    # nb: We're "overwriting" the "dump" variable here to have only the stripped down info
    # in the concluded string to avoid "too much" noise in the reporting.
    if(version)
      concluded = version[0];

    if(!isnull(version[1]) && isnull(version[3]))
      vers = version[1];
    else if(!isnull(version[2]) && !isnull(version[3]))
      vers = version[2] + "." + version[3];

    if(!isnull(vers)) {
      # nb: Used in 2012/gb_database_open_access_vuln.nasl to report an "Open" Database.
      # These keys should be only set if it was possible to grab the version without authentication.
      set_kb_item(name:"PostgreSQL/Remote/" + port + "/Ver", value:vers);
      set_kb_item(name:"OpenDatabase/found", value:TRUE);
    }

    if(isnull(vers)) {
      login = script_get_preference("Postgres Username:", id:1);
      if(!login)
        login = "postgres";

      password = script_get_preference("Postgres Password:", id:2);
      if(!password)
        password = "postgres";

      vers = check_login(user:login, password:password, port:port);
      # nb: No need to set a "concluded" string as it is passed "globally" by this function.
    }
  }

  if(isnull(vers))
    vers = "unknown";

  service_register(port:port, proto:"postgresql");

  install = port + "/tcp";

  set_kb_item(name:"postgresql/detected", value:TRUE);
  set_kb_item(name:"postgresql/tcp/detected", value:TRUE);
  set_kb_item(name:"postgresql/tcp/port", value:port);
  set_kb_item(name:"postgresql/tcp/" + port + "/installs", value:port + "#---#" + install + "#---#" + vers + "#---#" + concluded);

  log_message(port:port, data:"A PostgreSQL service has been identified on this port.");
}

exit(0);
