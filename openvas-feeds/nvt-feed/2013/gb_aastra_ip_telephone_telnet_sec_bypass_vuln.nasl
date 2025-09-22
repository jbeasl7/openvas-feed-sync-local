# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803190");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-09 15:08:24 +0530 (Tue, 09 Apr 2013)");
  script_name("Aastra IP Telephone Hardcoded Credentials (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Default Accounts");
  script_require_ports("Services/telnet", 23);
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("telnet/vxworks/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Apr/42");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/526207");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/aastra-ip-telephone-hardcoded-password");

  script_tag(name:"insight", value:"Aastra 6753i IP Phone installs with default hardcoded
  administrator credentials (username/password combination).");

  script_tag(name:"solution", value:"Upgrade to latest version of Aastra 6753i IP Telephone.");

  script_tag(name:"summary", value:"Aastra IP Telephone is using known hardcoded credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to access the device
  and gain privileged access.");

  script_tag(name:"affected", value:"Aastra 6753i IP Telephone.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

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
if(!banner || "VxWorks login:" >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:string("admin","\r\n"));
res = recv(socket:soc, length:4096);

if("Password:" >< res) {
  send(socket:soc, data:string("[M]qozn~","\r\n"));
  res = recv(socket:soc, length:4096);
  if("->" >< res && "Login incorrect" >!< res && "Password:" >!< res) {
    report = "It was possible to login with the following hardcoded credentials: 'admin:[M]qozn~'";
    security_message(port:port, data:report);
    close(soc);
    exit(0);
  }
}

close(soc);
exit(99);
