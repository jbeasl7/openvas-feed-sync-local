# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800258");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0590", "CVE-2009-0591", "CVE-2009-0789");
  script_name("OpenSSL Multiple Vulnerabilities (Mar 2009) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34411");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34256");
  script_xref(name:"URL", value:"http://www.openssl.org/news/secadv_20090325.txt");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Mar/1021905.html");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause memory access violation,
  security bypass or can cause denial of service.");

  script_tag(name:"affected", value:"OpenSSL version prior to 0.9.8k on all running platform.");

  script_tag(name:"insight", value:"- error exists in the 'ASN1_STRING_print_ex()' function when
  printing 'BMPString' or 'UniversalString' strings which causes invalid memory access violation.

  - 'CMS_verify' function incorrectly handles an error condition when processing malformed signed
  attributes.

  - error when processing malformed 'ASN1' structures which causes invalid memory access
  violation.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 0.9.8k.");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

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

if( version_is_less( version:vers, test_version:"0.9.8k" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.9.8k", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
