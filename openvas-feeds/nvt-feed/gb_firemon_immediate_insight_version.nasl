# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140107");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-29 10:07:33 +0100 (Thu, 29 Dec 2016)");
  script_name("FireMon Immediate Insight Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of FireMon Immediate Insight");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "firemon/immediate_insight/detected");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! port = kb_ssh_transport() ) exit( 0 );
if( ! sock = ssh_login_or_reuse_connection() ) exit( 0 );

buf = ssh_cmd( socket:sock, cmd:"PATH=/home/insight/app/utils/:$PATH /home/insight/app/utils/status" );
# System Status - Quick Check
# =============================
# --------------------------------------------------------------------
# Server IP: 192.168.2.51
# Personality: server
#
# Immediate Insight 2016 -- version: app-2016-10-18
# Search engine version: search-2.1.2
#
# Data Marshal: Running
# UI Marshal: Running
# Marshal Server: Running
# Agent: Running
# Search Engine: Running
# Search Engine Health: green
# Search Engine Memory: 4GB
#
# Data Storage (pct used):   1%
# System Storage (pct used):  27%
# System Log Storage (pct used):   1%
#
# Total System RAM: 7GB
# Free System RAM: 2GB
# %Cpu(s):  0.4 us,  0.3 sy,  0.0 ni, 99.2 id,  0.0 wa,  0.0 hi,  0.1 si,  0.0 st
#
# DNS Servers: 192.168.2.1
# Internet Access: yes
# Server Time: Thu Dec 29 10:16:40 CET 2016
# Server Timezone: Europe/Berlin
# NTP Servers: time.nist.gov time-nw.nist.gov

close( sock );

if( "Immediate Insight" >!< buf ) exit( 0 );

set_kb_item( name:"firemon/immediate_insight/status", value:buf );

cpe = 'cpe:/a:firemon:immediate_insight';
version = 'unknown';

lines = split( buf );

foreach line ( lines )
{
  if( line =~ 'Immediate Insight.* version: ' )
  {
    v = eregmatch( pattern:'Immediate Insight.* version: ([^\r\n]+)', string:line );
    break;
  }
}

if( ! isnull( v[1] ) )
{
  version = v[1]; # app-2016-10-18
  cpe += ':' + version;
  set_kb_item( name:"firemon/immediate_insight/version", value:version );
}

register_product( cpe:cpe, location:"ssh", port:port, service:"ssh" );

report = build_detection_report( app:"FireMon Immediate Insight", version:version, install:"ssh", cpe:cpe, concluded:v[0] );

log_message( port:port, data:report );

exit( 0 );

