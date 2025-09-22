# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103551");
  script_version("2025-09-09T05:38:49+0000");
  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2001-0645",
                "CVE-2002-1809",
                "CVE-2004-1532",
                "CVE-2004-2357",
                "CVE-2006-1451",
                "CVE-2007-2554",
                "CVE-2007-6081",
                "CVE-2009-0919",
                "CVE-2014-3419",
                "CVE-2015-4669",
                "CVE-2016-6531",
                "CVE-2018-15719",
                "CVE-2024-22901"
               );
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-08-23 10:38:09 +0200 (Thu, 23 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-07 17:37:28 +0000 (Wed, 07 Feb 2024)");
  script_name("MySQL / MariaDB Default Credentials (MySQL Protocol)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("mysql_mariadb/remote/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"It was possible to login into the remote MySQL using default
  credentials.");

  script_tag(name:"affected", value:"The following products are know to use such weak credentials:

  - CVE-2001-0645: Symantec/AXENT NetProwler 3.5.x

  - CVE-2002-1809: Windows binary release of MySQL 3.23.2 through 3.23.52

  - CVE-2004-1532: AppServ 2.5.x and earlier

  - CVE-2004-2357: Proofpoint Protection Server

  - CVE-2006-1451: MySQL Manager in Apple Mac OS X 10.3.9 and 10.4.6

  - CVE-2007-2554: Associated Press (AP) Newspower 4.0.1 and earlier

  - CVE-2007-6081: AdventNet EventLog Analyzer build 4030

  - CVE-2009-0919: XAMPP

  - CVE-2014-3419: Infoblox NetMRI before 6.8.5

  - CVE-2015-4669: Xsuite 2.x

  - CVE-2016-6531, CVE-2018-15719: Open Dental before version 18.4

  - CVE-2024-22901: Vinchin Backup & Recovery 7.2 and prior

  Other products might be affected as well.");

  script_tag(name:"solution", value:"- Change the password as soon as possible

  - Contact the vendor for other possible fixes / updates");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("byte_func.inc");
include("host_details.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cpe_list = make_list("cpe:/a:oracle:mysql",
                     "cpe:/a:mariadb:mariadb");

if(!infos = get_app_port_from_list(cpe_list:cpe_list))
  exit(0);

port = infos["port"];
cpe  = infos["cpe"];

if(get_kb_item("MySQL/" + port + "/blocked"))
  exit(0);

if(!get_app_location(cpe:cpe, port:port, nofork:TRUE))
  exit(0);

# nb:
# - Use "<none>" for an empty password
# - If ever required we could also change the ":" separator to something else if e.g.
#   a password containing the ":" should be added
creds = make_list(

  # CVE-2001-0645: via the "admin" password
  # CVE-2014-3419: Infoblox NetMRI before 6.8.5 has a default password of admin for the "root" MySQL database account
  "root:admin",

  "root:root",
  "root:mysql",
  "root:password",
  "root:passw0rd",
  "root:123456",
  "root:12345678",
  "root:mysqladmin",
  "root:qwerty",
  "root:letmein",
  "root:database",

  # Metasploitable 2: https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/#Weak-Passwords
  # CVE-2001-0645: using a blank password
  # CVE-2002-1809: has a NULL root password
  # CVE-2004-1532: https://marc.info/?l=bugtraq&m=110079586328430&w=2 has "the program comes in default user (Root) and empty password"
  # CVE-2004-2357: does not require a password for the root user of MySQL
  # CVE-2006-1451: which causes the MySQL root password to be blank
  # CVE-2007-2554: uses a default blank password for the MySQL root account
  # CVE-2007-6081: with a default "root" account without a password
  # CVE-2009-0919: a blank default password for the "root" account within the included MySQL installation
  # CVE-2015-4669: The MySQL "root" user in Xsuite 2.x does not have a password set
  # CVE-2016-6531: "has a hardcoded MySQL root password*snip*there is indeed a default blank password"
  # CVE-2018-15719: "uses the default credentials of "root" with a blank password"
  "root:<none>",

   # CVE-2024-22901 from https://blog.leakix.net/2024/01/vinchin-backup-rce-chain/#hardcoded-database-credentials-and-configuration-flaw-cve-2024-22901
  "vinchin:yunqi123456"
);

# nb: In the initial version of this VT it jumped out after the first failed connection but we want
# to try a little bit "harder" for connectivity issue cases and similar.
max_failed_count = 3;
cur_failed_count = 0;

# TBD: Put this / parts of it into a function? Some code is shared with e.g.:
# - 2012/gb_scrutinizer_54731.nasl
# - 2016/gb_blackstratus_LOGStorm_mysql_htr_login.nasl

foreach cred(creds) {

  cred_split = split(cred, sep:":", keep:FALSE);
  # nb: Shouldn't happen but we're checking it anyway...
  if(!cred_split || max_index(cred_split) != 2)
    continue;

  if(cur_failed_count >= max_failed_count)
    exit(0);

  if(!sock = open_sock_tcp(port)) {
    cur_failed_count++;
    continue;
  }

  res = recv(socket:sock, length:4);
  if(!res || strlen(res) != 4) {
    cur_failed_count++;
    close(sock);
    continue;
  }

  ver = "";
  pass = "";
  req = "";
  native = FALSE;

  # - https://web.archive.org/web/20210614014328/https://dev.mysql.com/doc/internals/en/client-server-protocol.html
  # - https://web.archive.org/web/20210506172939/https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV9
  # - https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
  # - https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v9.html
  # - https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
  #
  # nb:
  # - Packet Length seems to be 4 (checked above) for protocol version 9 and below
  # - With protocol version 10 it might be longer
  plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);
  res = recv(socket:sock, length:plen);

  if("mysql_native_password" >< res)
    native = TRUE;

  for(i = 0; i < strlen(res); i++) {
    if(ord(res[i]) != 0) {
      ver += res[i];
    } else {
      break;
    }
  }

  p = strlen(ver);
  if(p < 5) {
    close(sock);
    continue;
  }

  if(!caps = substr(res, 14 + p, 15 + p)) {
    close(sock);
    continue;
  }

  caps = ord(caps[0]) | ord(caps[1]) << 8;
  proto_is_41 = (caps & 512);
  if(!proto_is_41) {
    close(sock);
    continue;
  }

  username = cred_split[0];
  password = cred_split[1];
  if(password == "<none>")
    password = "";

  salt = substr(res, 5 + p, 12 + p);

  if(strlen(res) > (44 + p))
    salt += substr(res, 32 + p, 43 + p);

  sha_pass1 = SHA1(password);
  sha_pass2 = SHA1(sha_pass1);
  sha_pass3 = SHA1(salt + sha_pass2);

  l = strlen(sha_pass3);

  for(i = 0; i < l; i++)
    pass += raw_string(ord(sha_pass1[i]) ^ ord(sha_pass3[i]));

  req = raw_string(0x05, 0xa6, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00);

  req += raw_string(username, 0x00);

  if(strlen(password) > 0)
    req += raw_string(0x14, pass);
  else
    req += raw_string(0x00);

  if(native)
    req += raw_string(0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00);

  len = strlen(req);
  req = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x01) + req;

  send(socket:sock, data:req);
  res = recv(socket:sock, length:4);

  if(!res || strlen(res) < 4) {
    close(sock);
    continue;
  }

  plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);

  res = recv(socket:sock, length:plen);
  if(!res || strlen(res) < plen) {
    close(sock);
    continue;
  }

  errno = ord(res[2]) << 8 | ord(res[1]);

  if(errno > 0 || errno == "") {
    close(sock);
    continue;
  }

  cmd = "show databases";
  len = strlen(cmd) + 1;
  req = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x00, 0x03, cmd);

  send(socket:sock, data:req);

  z = 0;
  while(TRUE) {

    z++;
    if(z > 15) {
      # nb: The count is also raised here as the service is very likely "broken" in this case
      cur_failed_count++;
      break;
    }

    res = recv(socket:sock, length:4);
    if(!res || strlen(res) < 4)
      break;

    plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);

    res = recv(socket:sock, length:plen);
    if(!res || strlen(res) < plen)
      break;

    if("information_schema" >< res) {
      close(sock);

      data = 'It was possible to login as user "' + username + '"';

      if(strlen(password) > 0)
        data += ' with password "' + password + '".';
      else
        data += " with an empty password.";

      security_message(port:port, data:data);
      exit(0);
    }
  }
  close(sock);
}

exit(99);
