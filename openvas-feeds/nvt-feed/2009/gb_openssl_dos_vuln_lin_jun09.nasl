# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800809");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-12 17:18:17 +0200 (Fri, 12 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1386");
  script_name("Denial Of Service Vulnerability in OpenSSL (Jun 2009) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://cvs.openssl.org/chngview?cn=17369");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35174");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/06/02/1");
  script_xref(name:"URL", value:"http://rt.openssl.org/Ticket/Display.html?id=1679&user=guest&pass=guest");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause DTLS server crash.");

  script_tag(name:"affected", value:"OpenSSL version prior to 0.9.8i.");

  script_tag(name:"insight", value:"A NULL pointer dereference error in ssl/s3_pkt.c file which does not properly
  check the input packets value via a DTLS ChangeCipherSpec packet that occurs before ClientHello.");

  script_tag(name:"summary", value:"OpenSSL is prone to a Denial of Service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 0.9.8i or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
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

if( version_is_less( version:vers, test_version:"0.9.8i" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.9.8i", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
