# SPDX-FileCopyrightText: 2002 Jason Lidow <jason@brandx.net>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11151");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5803");
  script_cve_id("CVE-2002-1521");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Webserver 4D Cleartext Passwords");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Jason Lidow <jason@brandx.net>");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Web_Server_4D/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Contact the vendor for an update.");

  script_tag(name:"summary", value:"The remote host is running Webserver 4D 3.6 or lower.

  Version 3.6 of this service stores all usernames and passwords in cleartext.
  File: C:\Program Files\MDG\Web Server 4D 3.6.0\Ws4d.4DD");

  script_tag(name:"impact", value:"A local attacker may use this flaw to gain unauthorized privileges
  on this host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(!banner || "Web_Server_4D" >!< banner)
  exit(0);

line = egrep(pattern:"^Server.*", string:banner);
if(line) {
  report = "The following banner was received: " + line;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
