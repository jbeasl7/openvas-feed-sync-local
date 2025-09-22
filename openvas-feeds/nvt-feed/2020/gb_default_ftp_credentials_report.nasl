# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108718");
  script_version("2025-05-13T05:41:39+0000");
  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-1999-0501",
                "CVE-1999-0502",
                "CVE-1999-0507",
                "CVE-1999-0508",
                "CVE-2001-1594",
                "CVE-2013-7404",
                "CVE-2014-9198",
                "CVE-2015-7261",
                "CVE-2016-8731",
                "CVE-2017-8218",
                "CVE-2018-9068",
                "CVE-2018-17771",
                "CVE-2018-19063",
                "CVE-2018-19064"
               );
  script_tag(name:"last_modification", value:"2025-05-13 05:41:39 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2020-03-05 14:02:28 +0000 (Thu, 05 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FTP Brute Force Logins With Default Credentials Reporting");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("gb_default_ftp_credentials.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("default_ftp_credentials/started");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs
  # to choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd
  # database.

  script_tag(name:"summary", value:"It was possible to login into the remote FTP server using
  weak/known credentials.");

  script_tag(name:"vuldetect", value:"Reports weak/known credentials detected by the VT
  'FTP Brute Force Logins With Default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108717).");

  script_tag(name:"insight", value:"The following devices are / software is known to be affected:

  - CVE-2001-1594: Codonics printer FTP service as used in GE Healthcare eNTEGRA P&R

  - CVE-2013-7404: GE Healthcare Discovery NM 750b

  - CVE-2014-9198: Schneider Electric ETG3000 FactoryCast HMI gateways

  - CVE-2015-7261: QNAP iArtist Lite distributed with QNAP Signage Station

  - CVE-2016-8731: Foscam C1 devices

  - CVE-2017-8218: vsftpd on TP-Link C2 and C20i devices

  - CVE-2018-9068: IMM2 for IBM and Lenovo System x

  - CVE-2018-17771: Ingenico Telium 2 PoS terminals

  - CVE-2018-19063, CVE-2018-19064: Foscam C2 and Opticam i5 devices

  Note: As the VT 'FTP Brute Force Logins With Default Credentials' (OID:
  1.3.6.1.4.1.25623.1.0.108717) might run into a timeout the actual reporting of this vulnerability
  takes place in this VT instead.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to e.g. gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );

credentials = get_kb_list( "default_ftp_credentials/" + port + "/credentials" );
if( ! isnull( credentials ) ) {

  report = 'It was possible to login with the following credentials <User>:<Password>\n\n';

  # Sort to not report changes on delta reports if just the order is different
  credentials = sort( credentials );

  foreach credential( credentials ) {
    report += credential + '\n';
    vuln = TRUE;
  }
}

if( vuln ) {
  c = get_kb_item( "default_ftp_credentials/" + port + "/too_many_logins" );
  if( c ) {
    report += '\nRemote host accept more than ' + c + ' logins. This could indicate some error or some "broken" device.\nScanner stops testing for default logins at this point.';
  }
  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );
