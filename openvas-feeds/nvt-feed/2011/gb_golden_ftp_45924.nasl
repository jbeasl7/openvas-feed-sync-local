# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103037");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-01-20 13:02:23 +0100 (Thu, 20 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-6576");
  script_name("Golden FTP Server Malformed Message Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/golden_tfp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45924");
  script_xref(name:"URL", value:"http://www.mediafire.com/?jej19gc93zjbiyu");

  script_tag(name:"summary", value:"Golden FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Exploits will cause the application to crash, denying service to
  legitimate users.");

  script_tag(name:"affected", value:"Golden FTP Server 4.70 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );
if( ! banner || "Golden FTP" >!< banner )
  exit( 0 );

version = eregmatch( pattern:"Golden FTP Server ready v([0-9.]+)", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_less_equal( version:version[1], test_version:"4.70" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
