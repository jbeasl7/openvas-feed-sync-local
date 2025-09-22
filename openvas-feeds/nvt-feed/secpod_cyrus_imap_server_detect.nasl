# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902220");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Cyrus IMAP Server Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl", "popserver_detect.nasl");
  script_require_ports("Services/imap", 143, 993, "Services/pop3", 110, 995);
  script_mandatory_keys("pop3_imap_or_smtp/banner/available");

  script_tag(name:"summary", value:"This script finds the running version of Cyrus IMAP Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("pop3_func.inc");
include("imap_func.inc");
include("host_details.inc");
include("cpe.inc");
include("port_service_func.inc");

ports = imap_get_ports();
foreach port( ports ) {

  banner = imap_get_banner( port:port );
  if( ! banner )
    continue;

  if( "Cyrus IMAP" >< banner && "server ready" >< banner ) {

    version = "unknown";
    install = port + "/tcp";

    # e.g. * OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE STARTTLS AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5 AUTH=DIGEST-MD5 SASL-IR] example.com Cyrus IMAP v2.4.17 server ready
    vers = eregmatch( pattern:"IMAP4? v?([0-9.]+)", string:banner );
    if( isnull( vers[1] ) ) {
      # e.g. * ID ("name" "Cyrus IMAPD" "version" "2.5.10-Debian-2.5.10-3+deb9u1 be9a1799 2016-10-18" "vendor" "Project Cyrus"
      vers = eregmatch( pattern:'"version" "([0-9.]+)', string:banner );
    }

    if( ! isnull( vers[1] ) )
      version = vers[1];

    set_kb_item( name:"cyrus/imap_server/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cyrus:imap:" );
    if( ! cpe )
      cpe = "cpe:/a:cyrus:imap";

    register_product( cpe:cpe, location:install, port:port, service:"imap" );

    log_message( data:build_detection_report( app:"Cyrus IMAP Server",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:banner ),
                 port:port );

    # TODO: Remove once the existing CVEs are updated by the NVD to point to the new CPE
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cmu:cyrus_imap_server:" );
    if( ! cpe )
      cpe = "cpe:/a:cmu:cyrus_imap_server";

    register_product( cpe:cpe, location:install, port:port, service:"imap" );
  }
}

port = pop3_get_port( default:110 );
banner = pop3_get_banner( port:port );
if( ! banner )
  exit( 0 );

if( "Cyrus POP3" >< banner && "server ready" >< banner ) {

  version = "unknown";
  install = port + "/tcp";

  # e.g. +OK example.com Cyrus POP3 v2.4.17 server ready <123@example.com>
  vers = eregmatch( pattern:"POP3 v([0-9.]+)", string:banner );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  set_kb_item( name:"cyrus/imap_server/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cyrus:imap:" );
  if( ! cpe )
    cpe = "cpe:/a:cyrus:imap";

  register_product( cpe:cpe, location:install, port:port, service:"pop3" );

  log_message( data:build_detection_report( app:"Cyrus IMAP Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:banner ),
               port:port );

  # TODO: Remove once the existing CVEs are updated by the NVD to point to the new CPE
  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cmu:cyrus_imap_server:" );
  if( ! cpe )
    cpe = "cpe:/a:cmu:cyrus_imap_server";

  register_product( cpe:cpe, location:install, port:port, service:"pop3" );
}

exit( 0 );
