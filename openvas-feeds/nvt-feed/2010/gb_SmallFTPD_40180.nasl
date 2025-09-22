# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100642");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-17 12:46:01 +0200 (Mon, 17 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SmallFTPD 'DELE' Command Remote Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/smallftpd/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40180");

  script_tag(name:"summary", value:"SmallFTPD is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Successful attacks will cause the application to crash, creating a denial-of-
  service condition.");

  script_tag(name:"affected", value:"SmallFTPD 1.0.3 is vulnerable. Other versions may also be affected.");

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
if( "smallftpd" >!< banner ) exit( 0 );

version = eregmatch( pattern:"smallftpd ([0-9.]+)", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_less_equal( version:version[1], test_version:"1.0.3" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
