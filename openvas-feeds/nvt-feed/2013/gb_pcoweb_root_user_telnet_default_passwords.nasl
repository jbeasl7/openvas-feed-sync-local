# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103717");
  script_version("2024-11-19T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-19 05:05:41 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"creation_date", value:"2013-05-23 11:24:55 +0200 (Thu, 23 May 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-10 21:50:00 +0000 (Mon, 10 Feb 2020)");

  # nb: The hard-coded credentials are not named but it is very likely that one of the included
  # ones are matching so it was added here as a reference.
  script_cve_id("CVE-2019-13553");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("CAREL pCOWeb 'root' User Default Passwords (Telnet)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/carel/pcoweb/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote CAREL pCOWeb based device is using a known default
  password for the administrative 'root' account.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to login via Telnet as user 'root'
  with known default passwords.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Login with Telnet or HTTP and change the password.");

  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2019-013/-unsafe-storage-of-credentials-in-carel-pcoweb-hvac");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2019/Oct/45");
  script_xref(name:"URL", value:"https://www.us-cert.gov/ics/advisories/icsa-19-297-01");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default:23);
banner = telnet_get_banner(port:port);
if(!banner || !egrep(string:banner, pattern:"pCOWeb[^ ]* login:", icase:FALSE))
  exit(0);

username = "root";
cmd = "id";

foreach password(make_list("froot", "frootSX4jfH")) {

  if(!soc = open_sock_tcp(port))
    continue;

  res = telnet_negotiate(socket:soc);
  if(!res || !egrep(string:res, pattern:"pCOWeb[^ ]* login:", icase:FALSE)) {
    close(soc);
    continue;
  }

  send(socket:soc, data:username + '\r\n');
  res = recv(socket:soc, length:4096);
  if(!res || "Password:" >!< res) {
    close(soc);
    continue;
  }

  send(socket:soc, data:password + '\r\n');
  res = recv(socket:soc, length:4096);
  if(!res || "Login incorrect" >< res) {
    close(soc);
    continue;
  }

  if(res !~ "\[root@pCOWeb.*(root|~)\]#" && res !~ "Executing profile.+/s?bin") {
    close(soc);
    continue;
  }

  send(socket:soc, data:cmd + '\r\n');
  res = recv(socket:soc, length:8192);
  telnet_close_socket(socket:soc, data:res);

  if(res && res =~ "uid=0\(root\) gid=0\(root\)") {
    report = 'It was possible to login as "' + username + '" with password "' + password +
             '" and to execute the command "' + cmd + '". Result:\n\n' + res;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
