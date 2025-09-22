# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103606");
  script_cve_id("CVE-2011-0354");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-12-20T05:05:58+0000");

  script_name("Cisco TANDBERG C Series and E/EX Series Default Credentials (SSH)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46107");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/ps11422/products_security_advisory09186a0080b69541.shtml");
  script_xref(name:"URL", value:"http://www.tandberg.com/support/video-conferencing-software-download.jsp?t=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/516126");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/436854");

  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-11-14 11:19:49 +0100 (Wed, 14 Nov 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"The vendor has released an advisory along with fixes. Please see the
  referenced advisory for more information.");

  script_tag(name:"summary", value:"Cisco TANDBERG C Series Endpoints and E/EX Series Personal Video
  devices are using known default credentials.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain unauthorized root access to
  the affected devices. Successful exploits will result in the complete compromise of the affected device.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);

if(ssh_dont_try_login(port:port))
  exit(0);

# nb: No need to continue/start if we haven't received any banner...
if(!ssh_get_serverbanner(port:port))
  exit(0);

if(!sock = open_sock_tcp(port))
  exit(0);

login = ssh_login(socket:sock, login:"root", password:"");
if(login == 0) {

  cmd = ssh_cmd(socket:sock, cmd:"ls -l /apps/bin/tandberg");
  close(sock);

  if(eregmatch(pattern:"-rwx.*root.*/apps/bin/tandberg", string:cmd)) {
    security_message(port:port);
    exit(0);
  }
}

if(sock)close(sock);

exit(0);
