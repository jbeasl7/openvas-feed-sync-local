# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108081");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-10 10:55:08 +0100 (Fri, 10 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AKIF Orientierungshilfe Windows 10: Fehler");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Policy");
  script_dependencies("Policy/gb_policy_orientierungshilfe_win10.nasl");
  script_mandatory_keys("policy/orientierungshilfe_win10/error");

  script_tag(name:"summary", value:"Listet alle Fehler der 'AKIF Orientierungshilfe Windows 10 Uberpruefung' auf.");

  script_tag(name:"qod", value:"98");

  exit(0);
}

error = get_kb_item( "policy/orientierungshilfe_win10/error" );
if( ! error ) exit( 0 );

if( "Es koennen keine Ueberpruefungen durchgefuehrt werden." >< error ) {
  report = 'Es trat folgender Fehler auf:\n' + error + '\n';
  log_message( data:report, port:0 );
} else {

  error = split( error, sep:"#-#", keep:FALSE );

  report = max_index( error ) + ' Fehler:\n\n';

  foreach line( error ) {
    entry = split( line, sep:"||", keep:FALSE );
    report += "Beschreibung:             " + entry[0] + '\n';
    report += "Nummerierung:             " + entry[1] + '\n';
    report += "Ueberpruefung:            " + entry[2] + '\n';
    if( "Registry" >< entry[2] ) {
      report += "Registry-Key:             " + entry[3] + '\n';
      report += "Registry-Name:            " + entry[4] + '\n';
      report += "Registry-Typ:             " + entry[5] + '\n';
      report += "Erwarteter Registry-Wert: " + entry[6] + '\n';
      report += "Grund:                    " + entry[7] + '\n';
    } else if( "Service" >< entry[2] ) {
      report += "Service-Name:             " + entry[3] + '\n';
      report += "Erwarteter Startup-Type:  " + entry[4] + '\n';
      report += "Grund:                    " + entry[5] + '\n';
    }
    report += '\n';
  }
  log_message( data:report, port:0 );
}

exit( 0 );
