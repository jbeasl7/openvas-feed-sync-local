# SPDX-FileCopyrightText: 2004 Audun Larsen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12069");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("SMC2804WBR Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2004 Audun Larsen");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the administrator password.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"summary", value:"The remote host is a SMC2804WBR access point.

  This host is installed with a default administrator
  password (smcadmin) which has not been modified.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to gain control over
  this host using the default password.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
res = http_get_cache(item:"/", port:port);
if(!res)
  exit(0);

if("SMC2804WBR" >< res && "Please enter correct password for Administrator Access. Thank you." >< res) {

  host = http_host_name( port:port );
  variables = string("page=login&pws=smcadmin");
  req = string("POST /login.htm HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(!buf)
    exit(0);

  if("<title>LOGIN</title>" >!< buf) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
