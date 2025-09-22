# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900024");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2008-3459");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("OpenVPN Client RCE Vulnerability");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2316");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30532");
  script_xref(name:"URL", value:"http://openvpn.net/index.php/documentation/change-log/changelog-21.html");

  script_tag(name:"insight", value:"Application fails to properly validate the specially crafted input
  passed to lladdr/iproute configuration directives.");

  script_tag(name:"summary", value:"OpenVPN Client is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"affected", value:"Non-Windows OpenVPN client OpenVPN 2.1-beta14 to OpenVPN 2.1-rc8");

  script_tag(name:"solution", value:"Upgrade to higher version of Non-Windows OpenVPN client OpenVPN 2.1-rc9.");

  script_tag(name:"impact", value:"Remote attackers could execute arbitrary code on the Client.

  Successful exploitation requires,

  - the client to agree to allow the server to push configuration
  directives to it by including pull or the macro client in its configuration file.

  - the client successfully authenticates the server.

  - the server is malicious and has been compromised under the control of the attacker.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

vpnVer = ssh_cmd(socket:sock, cmd:"openvpn --version");
ssh_close_connection();
if(!vpnVer) exit(0);

if(egrep(pattern:"OpenVPN 2.1_(beta14|rc[0-8])($|[^.0-9])", string:vpnVer)){
  report = report_fixed_ver(installed_version:vpnVer, fixed_version:"2.1-rc9");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);