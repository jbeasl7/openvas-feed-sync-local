# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801993");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  # nb: Few CVEs/vulns to point out the cryptographic flaws.
  script_cve_id("CVE-2001-0361", "CVE-2001-0572", "CVE-2001-1473");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Deprecated SSH-1 Protocol Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("ssh_proto_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("SSH/supportedversions/available");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/684820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2344");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/6603");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass security
  restrictions and to obtain a client's public host key during a connection attempt and use it to open and
  authenticate an SSH session to another server with the same access.");

  script_tag(name:"affected", value:"Services providing / accepting the SSH protocol version SSH-1 (1.33 and 1.5).");

  script_tag(name:"solution", value:"Reconfigure the SSH service to only provide / accept the SSH protocol version SSH-2.");

  script_tag(name:"summary", value:"The host is running SSH and is providing / accepting one or more deprecated versions
  of the SSH protocol which have known cryptographic flaws.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );
versions = get_kb_list( "SSH/supportedversions/" + port );
if( ! versions )
  exit( 0 );

versions = sort( versions );

report = 'The service is providing / accepting the following deprecated versions of the SSH protocol which have known cryptographic flaws:\n';

foreach version( versions ) {

  # nb: Don't add 1.99 which is only a backward compatibility banner
  if( version == "1.33" || version == "1.5" ) {
    report += '\n' + version;
    VULN = TRUE;
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
