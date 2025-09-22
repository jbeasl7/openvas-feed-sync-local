# SPDX-FileCopyrightText: 2001 HD Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10673");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2000-1209");
  script_name("Microsoft SQL (MSSQL) Server Blank Password (TCP/IP Listener)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 HD Moore");
  script_family("Default Accounts");
  script_dependencies("gb_microsoft_sql_server_tcp_ip_listener_detect.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/mssql", 1433);
  script_mandatory_keys("microsoft/sqlserver/tcp_listener/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1281");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4797");

  script_tag(name:"summary", value:"The remote Microsoft SQL (MSSQL) Server has the default 'sa'
  account enabled without any password defined.");

  script_tag(name:"vuldetect", value:"Tries to login using the 'sa' account with a blank password
  via the Microsoft SQL protocol.");

  script_tag(name:"impact", value:"An attacker can use these accounts to read and/or modify data on
  the Microsoft SQL Server. In addition, the attacker may be able to launch programs on the target
  operating system.");

  script_tag(name:"solution", value:"Disable this account, or set a password to it. In addition to
  this, it is suggested you filter incoming TCP traffic to this port.

  For MSDE (OEM versions without MSQL console) :

  C:\MSSQL7\BINN\osql -U sa

  At the Password: prompt press <Enter>.

  Type the following replacing .password. with the password you wish to assign, in single quotes:

  EXEC sp_password NULL, .password., .sa.

  go

  exit");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("mssql.inc");

if(!port = get_app_port(cpe:CPE, service:"tcp_listener"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

sql_packet = mssql_make_login_pkt(username:"sa", password:"");

send(socket:soc, data:sql_packet);
# nb: mssql_pkt_lang is a global var passed from mssql.inc
send(socket:soc, data:mssql_pkt_lang);

r = mssql_recv(socket:soc);
close(soc);

if(strlen(r) > 10 && ord(r[8]) == 0xE3) {
  report = "The remote Microsoft SQL Server has a blank password for the 'sa' account.";
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
