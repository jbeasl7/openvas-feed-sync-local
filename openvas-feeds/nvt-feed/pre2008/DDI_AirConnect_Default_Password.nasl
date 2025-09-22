# SPDX-FileCopyrightText: 2002 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10961");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("AirConnect Default Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the password to something difficult to
  guess via the web interface.");

  script_tag(name:"summary", value:"This AirConnect wireless access point still has the
  default password set for the web interface.");

  script_tag(name:"impact", value:"This could be abused by an attacker to gain full control
  over the wireless network settings.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

url = "/";
req = http_get_req(port:port, url:url, add_headers:make_array("Authorization", "Basic Y29tY29tY29tOmNvbWNvbWNvbQ=="));
res = http_keepalive_send_recv(data:req, port:port);
if(!res)
  exit(0);

if("SecuritySetup.htm" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
