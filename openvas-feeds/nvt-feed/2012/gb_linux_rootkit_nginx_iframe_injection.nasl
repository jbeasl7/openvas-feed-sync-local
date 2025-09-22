# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802045");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2012-12-03 13:43:19 +0530 (Mon, 03 Dec 2012)");

  script_name("64-bit Debian Linux Rootkit with nginx Doing iFrame Injection - Active Check");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/94");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/172");
  script_xref(name:"URL", value:"http://blog.crowdstrike.com/2012/11/http-iframe-injecting-linux-rootkit.html");
  script_xref(name:"URL", value:"http://www.securelist.com/en/blog/208193935/New_64_bit_Linux_Rootkit_Doing_iFrame_Injections");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Malware");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/http/detected");

  script_tag(name:"impact", value:"Successful iframe injection leads redirecting to some malicious sites.");

  script_tag(name:"affected", value:"64-bit Debian Squeeze (kernel version 2.6.32-5-amd64) with nginx.");

  script_tag(name:"insight", value:"64-bit Debian Squeeze Linux Rootkit in combination with nginx launching
  iframe injection attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Debian Squeeze Linux Rootkit with nginx is prone to iframe injection.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

req = string( "GET / HTTP/1.1\r\n", "Hostttt ", host, "\r\n\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 400" &&
   egrep(string:res, pattern:"^[Ss]erver\s*:\s*nginx", icase:FALSE) &&
   egrep(pattern:"<iframe\s+src=.*</iframe>", string:res, icase:TRUE)){
  security_message(port:port);
  exit(0);
}

exit(99);
