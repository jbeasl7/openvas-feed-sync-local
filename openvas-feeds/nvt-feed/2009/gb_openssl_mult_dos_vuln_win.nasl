# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900654");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379");
  script_name("OpenSSL DTLS Packets Multiple DoS Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.slproweb.com/products/Win32OpenSSL.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35001");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35128");
  script_xref(name:"URL", value:"http://cvs.openssl.org/chngview?cn=18188");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause denial-of-service
  conditions, crash the client, and exhaust all memory.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 to version 0.9.8k on Windows.
  OpenSSL version 1.0.0 Beta2 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The library does not limit the number of buffered DTLS records with a
  future epoch.

  - An error when processing DTLS messages can be exploited to exhaust all
  available memory by sending a large number of out of sequence handshake messages.

  - A use-after-free error in the 'dtls1_retrieve_buffered_fragment()' function
  can be exploited to cause a crash in a client context.");

  script_tag(name:"solution", value:"Apply patches or upgrade to the latest version.");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple Denial of Service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"0.9.8", test_version2:"0.9.8k" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
