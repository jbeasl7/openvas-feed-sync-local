# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900119");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_cve_id("CVE-2008-4041");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Softalk Mail Server IMAP Denial of Service Vulnerability");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/softalk/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31715/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/495896");

  script_tag(name:"summary", value:"Softalk Mail Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"The issue is due to inadequate boundary checks on specially
  crafted IMAP commands. The service can by crashed sending malicious IMAP command sequences.");

  script_tag(name:"affected", value:"Softalk Mail Server versions 8.5.1 and prior on Windows (all).");

  script_tag(name:"solution", value:"Upgrade to Softalk Mail Server version 8.6.0 or later.");

  script_tag(name:"impact", value:"Successful exploitation crashes the affected server denying the
  service to legitimate users.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("imap_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = imap_get_port( default:143 );
banner = imap_get_banner( port:port );
if( ! banner )
  exit( 0 );

if( egrep( pattern:"Softalk Mail Server ([0-7]\..*|8\.([0-4](\..*)?|5(\.0" +
                   "(\..*)?)?|5\.1))[^.0-9]", string:banner ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
