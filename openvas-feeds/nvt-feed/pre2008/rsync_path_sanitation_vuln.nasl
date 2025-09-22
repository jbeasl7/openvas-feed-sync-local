# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14223");
  script_version("2023-08-01T13:29:10+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10938");
  script_cve_id("CVE-2004-0792");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("rsync path sanitation vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("gb_rsync_remote_detect.nasl");
  script_require_ports("Services/rsync", 873);
  script_mandatory_keys("rsync/protocol_banner/available");

  script_tag(name:"summary", value:"A vulnerability has been reported in rsync, which potentially can be exploited
  by malicious users to read or write arbitrary files on a vulnerable system.");

  script_tag(name:"impact", value:"There is a flaw in this version of rsync which, due to an input validation
  error, would allow a remote attacker to gain access to the remote system.");

  script_tag(name:"insight", value:"An attacker, exploiting this flaw, would need network access to the TCP port.

  Successful exploitation requires that the rsync daemon is *not* running chrooted.");

  script_tag(name:"solution", value:"Upgrade to rsync 2.6.3 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("rsync_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = rsync_get_port( default:873 );

protocol = get_kb_item( "rsync/protocol_banner/" + port );
if( ! protocol )
  exit( 0 );

# rsyncd speaking protocol 28 are not vulnerable
if( ereg( pattern:"(@RSYNCD:|protocol version) (1[0-9]|2[0-8])", string:protocol ) ) {
  report = "Detected and affected RSYNCD protocol: " + protocol;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
