# SPDX-FileCopyrightText: 2002 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10999");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("Linksys Router Default Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Please assign the web administration
  console a difficult to guess password.");

  script_tag(name:"summary", value:"This Linksys Router has the default password
  set for the web administration console.");

  script_tag(name:"impact", value:"This console provides read/write access to the
  router's configuration. An attacker could take advantage of this to reconfigure the
  router and possibly re-route traffic.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

# HTTP auth = ":admin"
# req = string("GET / HTTP/1.0\r\nAuthorization: Basic OmFkbWlu\r\n\r\n");

# HTTP auth = "admin:admin"
req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");

# nb: Both work, second is used to be RFC compliant.

buf = http_send_recv(port:port, data:req);

if( "Status.htm" >< buf && "DHCP.htm" >< buf && "Log.htm" >< buf && "Security.htm" >< buf ||
    ( "next_file=Setup.htm" >< buf && "Checking JavaScript Support" >< buf ) ) { #WAG120N
  security_message(port:port);
}
