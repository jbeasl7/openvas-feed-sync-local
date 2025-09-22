# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96056");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Printer Test SSL/TLS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "dont_print_on_printers.nasl");

  script_tag(name:"summary", value:"This plugin uses openssl to verify and Test TLS/SSL Certificates on
  CUPS and Printer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("http_func.inc");
include("ssl_funcs.inc");

if( get_kb_item( "Host/is_printer" ) ) Printer = "True";

ports = get_kb_list( "Ports/tcp/*" ); # We don't need TCP/PORTS here as no active check is done

if( isnull( ports ) ) Printer = "False";

foreach p( keys( ports ) ) {

  p = int(p - "Ports/tcp/");
  if( p == 35 || p == 2000 || p == 2501 || (p >= 3001 && p <= 3005) || (p >= 9100 && p <= 9300) || p == 10001) {
    Printer = "True";
  } else if( p == 631 ) {
    Printer = "IPP";
  }
}

if( ! Printer ) Printer = "False";

if( Printer == "IPP" ) {

  temp = get_tmp_dir();

  i = 0;
  argv[i++] = "openssl";
  argv[i++] = "s_client";
  argv[i++] = "-connect";
  argv[i++] = get_host_ip() + ":631";

  cert = pread( cmd:"openssl", argv:argv, cd:5 );
  fwrite( file:temp + get_host_ip() + "-GSHB_cert.txt",data:cert );

  if( "error" >!< cert && "connect:errno=29" >!< cert ) {
    s = 0;
    sargv[s++] = "sed";
    sargv[s++] = "-ne";
    sargv[s++] = "/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p";
    sargv[s++] = temp + get_host_ip() + "-GSHB_cert.txt";

    clearcert = pread( cmd:"sed", argv:sargv, cd:5 );
    unlink( temp + "GSHB_cert.txt" );
    fwrite( file:temp + get_host_ip() + "-GSHB_clearcert.txt",data:clearcert );

    o = 0;
    oargv[o++] = "openssl";
    oargv[o++] = "x509";
    oargv[o++] = "-issuer";
    oargv[o++] = "-subject";
    oargv[o++] = "-dates";
    oargv[o++] = "-hash";
    oargv[o++] = "-fingerprint";
    oargv[o++] = "-email";
    oargv[o++] = "-pubkey";
    oargv[o++] = "-alias";
    oargv[o++] = "-in";
    oargv[o++] = temp + get_host_ip() + "-GSHB_clearcert.txt";

    cert = pread( cmd:"openssl", argv:oargv, cd:5 );
    unlink( temp + get_host_ip() + "-GSHB_clearcert.txt" );
  } else if( "connect:errno=29" >< cert) {
    cert = "none";
  } else if ( "error" >< cert ) {
    cert = "error";
  }
}

if( ! cert ) cert = "none";

set_kb_item( name:"GSHB/IPP-Cert", value:cert );
set_kb_item( name:"GSHB/Printer", value:Printer );

exit( 0 );
