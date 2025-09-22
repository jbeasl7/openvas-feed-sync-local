# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108484");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2018-5407");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 16:58:00 +0000 (Fri, 18 Sep 2020)");
  script_tag(name:"creation_date", value:"2018-11-22 07:48:19 +0100 (Thu, 22 Nov 2018)");
  script_name("OpenSSL: Microarchitecture timing vulnerability in ECC scalar multiplication (CVE-2018-5407) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20181112.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/aab7c770353b1dc4ba045938c8fb446dd1c4531e");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/b18162a7c9bbfb57112459a4d6631fa258fd8c0cq");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105897");
  script_xref(name:"URL", value:"https://eprint.iacr.org/2018/1060.pdf");
  script_xref(name:"URL", value:"https://github.com/bbbrumley/portsmash");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45785/");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL ECC scalar multiplication, used in e.g. ECDSA and ECDH,
  has been shown to be vulnerable to a microarchitecture timing side channel attack.");

  script_tag(name:"impact", value:"An attacker with sufficient access to mount local timing attacks
  during ECDSA signature generation could recover the private key.");

  script_tag(name:"affected", value:"OpenSSL versions 1.1.0-1.1.0h and 1.0.2-1.0.2p.");

  script_tag(name:"solution", value:"Upgrade OpenSSL to version 1.0.2q, 1.1.0i or later. See the references for more details.");

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

if( version_in_range( version:vers, test_version:"1.1.0", test_version2:"1.1.0h" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.0i", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:vers, test_version:"1.0.2", test_version2:"1.0.2p" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.2q", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
