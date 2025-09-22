# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100453");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-20 10:52:14 +0100 (Wed, 20 Jan 2010)");
  script_cve_id("CVE-2010-1068");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("SurgeFTP 'surgeftpmgr.cgi' Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/surgeftp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37844");

  script_tag(name:"summary", value:"SurgeFTP is prone to multiple cross-site scripting vulnerabilities
  because the application fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in an administrator's
  browser session in the context of the affected site. This could potentially allow the attacker to
  steal cookie-based authentication credentials. Other attacks are also possible.");

  script_tag(name:"affected", value:"SurgeFTP 2.3a6 is vulnerable. Other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = ftp_get_port( default:21 );
if( ! banner = ftp_get_banner( port:port ) ) exit( 0 );
if( "SurgeFTP" >!< banner ) exit( 0 );

version = eregmatch( pattern:"SurgeFTP.*\(Version ([^)]+)\)", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_less_equal( version:version[1], test_version:"2.3a6" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
