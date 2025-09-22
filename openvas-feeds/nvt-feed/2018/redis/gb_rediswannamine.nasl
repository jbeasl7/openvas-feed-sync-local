# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108444");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-06-05 07:40:29 +0200 (Tue, 05 Jun 2018)");
  script_name("Redis Server compromised by 'RedisWannaMine' Attack");
  script_category(ACT_GATHER_INFO);
  script_family("Malware");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_redis_detect.nasl");
  script_require_ports("Services/redis", 6379);
  script_mandatory_keys("redis/installed");

  script_xref(name:"URL", value:"https://www.imperva.com/blog/2018/03/rediswannamine-new-redis-nsa-powered-cryptojacking-attack/");
  script_xref(name:"URL", value:"https://www.imperva.com/blog/2018/06/new-research-shows-75-of-open-redis-servers-infected/");

  script_tag(name:"summary", value:"The remote Redis server is unprotected and has been compromised
  via the 'RedisWannaMine' attack.");

  script_tag(name:"vuldetect", value:"The script is sending commands to the remote Redis server and
  checks for the following indicators of compromise (IOC):

  - datadir set to c:\temp, c:\tmp, /var/spool/cron, /etc/crontabs, /etc, /proc or /tmp

  - the existence of at least one of the following keys: trojan1, trojan2, backup1, backup2,
  backup3, crackit");

  script_tag(name:"impact", value:"The 'RedisWannaMine' drops a crypto miner on the target to misuse
  the host resources for crypto mining. Furthermore it will try to attack other hosts via the SMB
  attack 'WannaCry'.");

  script_tag(name:"affected", value:"All Redis server publicly accessible without authentication.");

  script_tag(name:"solution", value:"A whole cleanup of the infected system is recommended.
  Additionally block all traffic to the Redis server or enable authentication.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

dir_cmd = 'CONFIG GET dir\r\n';
send( socket:soc, data:dir_cmd );
dir_recv = recv( socket:soc, length:1024 );

keys_cmd = 'KEYS *\r\n';
send( socket:soc, data:keys_cmd );
keys_recv = recv( socket:soc, length:4096 );
close( soc );

report = 'The following IOCs have been found on the remote Redis server:\n\n';

if( found = egrep( string:dir_recv, pattern:"^(c:\\te?mp|/var/spool/cron|/etc/crontabs|/etc|/proc|/tmp)", icase:TRUE ) ) {
  report += "Command used: 'CONFIG GET dir'" + '\n';
  report += "Result: " + found;
  VULN = TRUE;
}

if( found = egrep( string:keys_recv, pattern:"^(trojan[0-9]|backup[0-9]|crackit)", icase:TRUE ) ) {
  if( VULN )
    report += '\n';
  report += "Command used: 'KEYS *'" + '\n';
  report += "Result: " + found;
  VULN = TRUE;
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
