# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800193");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_cve_id("CVE-2010-4094");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("IBM Rational Quality Manager and Rational Test Lab Manager Tomcat Default Account Vulnerability (HTTP)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44172");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-214");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Oct/1024601.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 9080);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code in the context of an affected application.");

  script_tag(name:"affected", value:"Versions prior to IBM Rational Quality Manager and IBM Test Lab
  Manager 7.9.0.3 build:1046.");

  script_tag(name:"insight", value:"The flaw exists within the installation of the bundled Tomcat
  server.

  The default ADMIN account is improperly disabled within 'tomcat-users.xml' with default password.
  A remote attacker can use this vulnerability to execute arbitrary code under the context of the
  Tomcat server.");

  script_tag(name:"solution", value:"Update to version 7.9.0.3 build 1046 or later.");

  script_tag(name:"summary", value:"The Apache Tomcat server in IBM Rational Quality Manager / IBM
  Rational Test Lab Manager has a default password for the ADMIN account.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:9080);

host = http_host_name(port:port);

req = string("GET /manager/html HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Authorization: Basic QURNSU46QURNSU4=\r\n",
             "\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) && "IBM Corporation" >< res &&
   ("deployConfig" >< res || "installConfig" >< res) &&
   ("deployWar" >< res || "installWar" >< res)) {
  security_message(port:port);
  exit(0);
}

exit(99);
