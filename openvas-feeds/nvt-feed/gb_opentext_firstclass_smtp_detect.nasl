# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113608");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-12-02 13:30:00 +0200 (Mon, 02 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenText FirstClass Detection (SMTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/opentext/firstclass/detected");

  script_tag(name:"summary", value:"SMTP based detection of OpenText FirstClass.");

  script_xref(name:"URL", value:"https://www.opentext.com/products-and-solutions/products/specialty-technologies/firstclass");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port( default: 25 );

if( ! banner = smtp_get_banner( port: port ) )
  exit( 0 );

if( banner =~ "FirstClass [A-Z]?SMTP" ) {

  set_kb_item( name: "opentext/firstclass/detected", value: TRUE );
  set_kb_item( name: "opentext/firstclass/smtp/detected", value: TRUE );
  set_kb_item( name: "opentext/firstclass/smtp/port", value: port );

  ver = eregmatch( string: banner, pattern: 'FirstClass [A-Z]?SMTP [^\n]*Server v([0-9.]+)', icase: TRUE );
  if( ! isnull( ver[1] ) ) {
    set_kb_item( name: "opentext/firstclass/smtp/concluded", value: ver[0] );
    set_kb_item( name: "opentext/firstclass/smtp/version", value: ver[1] );
  }
}

exit( 0 );
