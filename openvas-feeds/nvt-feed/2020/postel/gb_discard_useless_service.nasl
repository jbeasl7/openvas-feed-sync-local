# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postel:discard";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11367");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-09-22 10:18:28 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  # nb: It seems the discard service can get falsely detected due to e.g. SonicWall firewalls
  # activity, in some cases
  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-1999-0636");

  script_name("Check for discard Service (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Useless services");
  script_dependencies("shn_discard_tcp_detect.nasl");
  script_mandatory_keys("discard/detected");

  script_tag(name:"summary", value:"The remote host is running a 'discard' service. This service
  typically sets up a listening socket and will ignore all the data which it receives.

  This service is unused these days, so it is advised that you disable it.");

  script_tag(name:"vuldetect", value:"Checks whether a discard service is exposed on the target
  host by evaluating the info from the following service detection:

  - discard Service Detection (TCP) (OID: 1.3.6.1.4.1.25623.1.0.113757)");

  script_tag(name:"solution", value:"- Under Unix systems, comment out the 'discard' line in
  /etc/inetd.conf and restart the inetd process

  - Under Windows systems, set the following registry key to 0:

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpDiscard

  Then launch cmd.exe and type:

  net stop simptcp

  net start simptcp

  To restart the service.

  Notes:

  Some firewall devices are known to discard packets on the checked port 9/tcp or mimic such a
  service via other means. Scanning through a firewall should be generally avoided (Please see
  references).

  If the target was scanned through a firewall and it was determined / has been verified that no
  such service is running on the target please either:

  - create an override for this result

  - configure the firewall in a way that port 9/tcp is not reported as being open during the port
  scanning phase / it is not allowed to open a TCP connection to port 9/tcp on the target");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc863");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/read-before-use.html#scanning-through-network-equipment");

  exit(0);
}

include( "host_details.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! get_app_location( cpe: CPE, port: port, nofork: TRUE ) )
  exit( 0 );

report = "The discard service was detected on the target host.";
security_message( port: port, data: report );
exit( 0 );
