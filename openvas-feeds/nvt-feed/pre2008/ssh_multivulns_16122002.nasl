# SPDX-FileCopyrightText: 2002 Paul Johnston, Westpoint Ltd
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11195");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-1357", "CVE-2002-1358", "CVE-2002-1359", "CVE-2002-1360");
  script_name("SSH Multiple Vulns");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2002 Paul Johnston, Westpoint Ltd");
  script_family("Gain a shell remotely");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"solution", value:"Upgrade your SSH server to an unaffected version.");

  script_tag(name:"summary", value:"According to its banner, the remote SSH server is vulnerable to one or
  more of the following vulnerabilities:

  CVE-2002-1357 (incorrect length)

  CVE-2002-1358 (lists with empty elements/empty strings)

  CVE-2002-1359 (large packets and large fields)

  CVE-2002-1360 (string fields with zeros)");

  script_tag(name:"impact", value:"Some of these vulnerabilities may allow remote attackers to execute
  arbitrary code with the privileges of the SSH process, usually root.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);
banner = ssh_get_serverbanner(port:port);
if ( ! banner )
  exit(0);

# SSH-2.0-3.2.0 F-Secure SSH Windows NT Server
# versions up to 3.1.* affected
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) F-Secure SSH", string:banner, icase:TRUE))
{
  security_message(port:port);
}

# SSH-2.0-3.2.0 SSH Secure Shell Windows NT Server
# versions up to 3.1.* affected
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) SSH Secure Shell", string:banner, icase:TRUE))
{
  security_message(port:port);
}

# SSH-1.99-Pragma SecureShell 3.0
# versions up to 2.* affected
if(ereg(pattern:"^SSH-1.99-Pragma SecureShell ([12]\..*)", string:banner, icase:TRUE))
{
  security_message(port:port);
}
