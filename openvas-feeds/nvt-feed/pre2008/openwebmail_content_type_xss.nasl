# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openwebmail.acatysmoof:openwebmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12262");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Open WebMail Content-Type XSS");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OpenWebMail/detected");

  script_xref(name:"URL", value:"http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:05.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10667");
  script_xref(name:"URL", value:"http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt");
  script_xref(name:"URL", value:"http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt");

  script_tag(name:"solution", value:"Upgrade to Open WebMail version 2.32 20040603 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of Open WebMail whose
  version is 2.32 or earlier. Such versions are vulnerable to a cross
  site scripting attack whereby an attacker can cause a victim to
  unknowingly run arbitrary Javascript code by reading a MIME message
  with a specially crafted Content-Type or Content-Description header.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

# nb: intermediate releases of 2.32 from 20040527 - 20040602 are vulnerable, as are 2.32 and earlier releases.
pat = "^(1\.|2\.([0-2]|3[01]|32$|32 20040(5|60[12])))";
if( ereg( pattern:pat, string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.32 20040603" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
