# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111057");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-11-24 10:00:00 +0100 (Tue, 24 Nov 2015)");
  script_cve_id("CVE-2010-2772");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 16:44:42 +0000 (Tue, 13 Feb 2024)");
  script_name("Siemens WinCC Microsoft SQL (MSSQL) Server Default Credentials (TCP/IP Listener)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_microsoft_sql_server_tcp_ip_listener_detect.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/mssql", 1116);
  script_mandatory_keys("microsoft/sqlserver/tcp_listener/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41753");
  script_xref(name:"URL", value:"http://scadastrangelove.blogspot.de/2012/07/wincc-default-password-7-years-long.html");

  script_tag(name:"summary", value:"The remote Microsoft SQL (MSSQL) Server has Siemens WinCC
  related default credentials set.");

  script_tag(name:"vuldetect", value:"Tries to login with a number of known default credentials via
  the Microsoft SQL protocol.");

  script_tag(name:"insight", value:"It was possible to login with default credentials of
  'WinCCAdmin/2WSXcde.' and/or 'WinCCConnect/2WSXcder'.");

  script_tag(name:"impact", value:"An attacker can use these accounts to read and/or modify data on
  the Microsoft SQL Server. In addition, the attacker may be able to launch programs on the target
  operating system.");

  script_tag(name:"solution", value:"Update to version 7.0 SP2 Update 1 (7.0.2.1) or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

# nb:
# - This script is based on mssql_blank_password.nasl / mssql_brute_force.nasl
# - A dedicated VT has been used because the info / solution is different

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("mssql.inc");

if(!port = get_app_port(cpe:CPE, service:"tcp_listener"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

VULN = FALSE;
report = 'It was possible to login to the remote Microsoft SQL (MSSQL) Server with following known credentials:\n';

creds = make_array("WinCCAdmin", "2WSXcde.",
                   "WinCCConnect", "2WSXcder");

foreach username(keys(creds)) {

  if(!soc = open_sock_tcp(port))
    continue;

  password = creds[username];
  sql_packet = mssql_make_login_pkt(username:username, password:password);

  send(socket:soc, data:sql_packet);
  # nb: mssql_pkt_lang is a global var passed from mssql.inc
  send(socket:soc, data:mssql_pkt_lang);

  r = mssql_recv(socket:soc);
  close(soc);

  if(strlen(r) > 10 && ord(r[8]) == 0xE3) {
    report += '\nAccount: "' + username + '", Password: ' + password;
    VULN = TRUE;
  }
}

if(VULN) {
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
