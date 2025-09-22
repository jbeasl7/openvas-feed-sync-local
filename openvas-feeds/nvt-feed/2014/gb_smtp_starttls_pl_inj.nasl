# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103935");
  script_version("2023-10-31T05:06:37+0000");
  script_cve_id("CVE-2011-0411", "CVE-2011-1430", "CVE-2011-1431", "CVE-2011-1432",
                "CVE-2011-1506", "CVE-2011-1575", "CVE-2011-1926", "CVE-2011-2165");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-04-08 13:52:07 +0200 (Tue, 08 Apr 2014)");
  script_name("Multiple Vendors STARTTLS Implementation Plaintext Arbitrary Command Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl", "gb_starttls_smtp.nasl");
  script_mandatory_keys("smtp/starttls/supported");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46767");
  script_xref(name:"URL", value:"http://kolab.org/pipermail/kolab-announce/2011/000101.html");
  script_xref(name:"URL", value:"http://bugzilla.cyrusimap.org/show_bug.cgi?id=3424");
  script_xref(name:"URL", value:"http://cyrusimap.org/mediawiki/index.php/Bugs_Resolved_in_2.4.7");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/MAPG-8D9M4P");
  script_xref(name:"URL", value:"http://files.kolab.org/server/release/kolab-server-2.3.2/sources/release-notes.txt");
  script_xref(name:"URL", value:"http://www.postfix.org/CVE-2011-0411.html");
  script_xref(name:"URL", value:"http://www.pureftpd.org/project/pure-ftpd/news");
  script_xref(name:"URL", value:"http://www.watchguard.com/support/release-notes/xcs/9/en-US/EN_ReleaseNotes_XCS_9_1_1/EN_ReleaseNotes_WG_XCS_9_1_TLS_Hotfix.pdf");
  script_xref(name:"URL", value:"http://www.spamdyke.org/documentation/Changelog.txt");
  script_xref(name:"URL", value:"http://datatracker.ietf.org/doc/draft-josefsson-kerberos5-starttls/?include_text=1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/516901");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100134676");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100141041");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html");
  script_xref(name:"URL", value:"http://inoa.net/qmail-tls/vu555316.patch");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/555316");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary commands
  in the context of the user running the application. Successful exploits can allow attackers to
  obtain email usernames and passwords.");

  script_tag(name:"vuldetect", value:"Send a special crafted 'STARTTLS' request and check the
  response.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Multiple vendors' implementations of 'STARTTLS' are prone to a
  vulnerability that lets attackers inject arbitrary commands.");

  script_tag(name:"affected", value:"The following vendors are known to be affected:

  Ipswitch

  Kerio

  Postfix

  Qmail-TLS

  Oracle

  SCO Group

  spamdyke

  ISC");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port( default:25 );

if( ! get_kb_item( "smtp/" + port + "/starttls" ) )
  exit( 0 );

if( ! soc = smtp_open( port:port, data:smtp_get_helo_from_kb(port:port) ) )
  exit( 0 );

send( socket:soc, data:'STARTTLS\r\nNOOP\r\n' );
r = smtp_recv_line( socket:soc, code:"220" );
if( ! r ) {
  smtp_close( socket:soc, check_data:r );
  exit( 0 );
}

# nb: socket_negotiate_ssl() is "upgrading" the socket and the socket number stays the same if
# successful so we only need to check it like this. Furthermore if no SSL/TLS connection could be
# estabilshed socket_negotiate_ssl() will close the passed socket internally so we don't need to
# close it when doing the exit here.
if( ! socket_negotiate_ssl( socket:soc ) )
  exit( 0 );

s = smtp_recv_line( socket:soc, code:"250" );
smtp_close( socket:soc, check_data:s );
if( s ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
