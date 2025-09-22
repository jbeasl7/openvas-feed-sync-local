# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111031");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-26 12:00:00 +0200 (Wed, 26 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dovecot Detection (POP3/IMAP)");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl", "popserver_detect.nasl");
  script_require_ports("Services/imap", 143, 993, "Services/pop3", 110, 995);
  script_mandatory_keys("imap_or_pop3/dovecot/detected");

  script_tag(name:"summary", value:"The script checks the POP3/IMAP server
  banner for the presence of Dovecot.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("pop3_func.inc");
include("imap_func.inc");
include("port_service_func.inc");

cpe = "cpe:/a:dovecot:dovecot";

# e.g. for IMAP:
# * OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS LOGINDISABLED] Dovecot ready.
# * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED] Dovecot (Debian) ready.
#
# * ID ("name" "Dovecot")
#
# or POP3:
# +OK Dovecot ready.
# +OK Dovecot (Debian) ready.
pattern = "Dovecot ([a-zA-Z()]+ )?ready";

ports = imap_get_ports();
foreach port( ports ) {

  banner = imap_get_banner( port:port );
  id_banner = get_kb_item( "imap/fingerprints/" + port + "/id_banner" );

  if( egrep( pattern:pattern, string:banner, icase:TRUE ) ||
      "Dovecot" >< id_banner ) {

    version = "unknown";

    set_kb_item( name:"dovecot/detected", value:TRUE );
    set_kb_item( name:"dovecot/imap/detected", value:TRUE );
    set_kb_item( name:"dovecot/imap/port", value:port );

    # Format used in gb_dovecot_consolidation.nasl is:
    # Detection-Name#--#service#--#port#--#location#--#version#--#concluded
    set_kb_item( name:"dovecot/detection-info", value:"IMAP Banner#--#imap#--#" + port + "#--#" + port + "/tcp#--#" + version + "#--#" + chomp( banner ) );
  }
}

port   = pop3_get_port( default:110 );
banner = pop3_get_banner( port:port );

if( egrep( pattern:pattern, string:banner, icase:TRUE ) ) {

  version = "unknown";

  set_kb_item( name:"dovecot/detected", value:TRUE );
  set_kb_item( name:"dovecot/pop3/detected", value:TRUE );
  set_kb_item( name:"dovecot/pop3/port", value:port );

  # Format used in gb_dovecot_consolidation.nasl is:
  # Detection-Name#--#service#--#port#--#location#--#version#--#concluded
  set_kb_item( name:"dovecot/detection-info", value:"POP3 Banner#--#pop3#--#" + port + "#--#" + port + "/tcp#--#" + version + "#--#" + chomp( banner ) );
}

exit( 0 );
