# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813153");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-0732", "CVE-2018-0737");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:00:00 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-04-23 18:19:03 +0530 (Mon, 23 Apr 2018)");
  script_name("OpenSSL: 1.0.2 < 1.0.2p / 1.1.0 < 1.1.0i Multiple Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20180416.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104442");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20180612.txt");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q2/50");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/ea7abeeabf92b7aca160bdd0208636d4da69f4f4");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/3984ef0b72831da8b3ece4745cac4f8575b19098");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/6939eab03a6e23d2bd2c3f5e34fe1d48e542e787");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/349a41da1ad88ad87825414752a8ff5fdd6a6c3f");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to:

  - During key agreement in a TLS handshake using a DH(E) based ciphersuite a malicious server can send
  a very large prime value to the client (CVE-2018-0732).

  - The OpenSSL RSA Key generation algorithm has been shown to be vulnerable to a cache timing side channel
  attack (CVE-2018-0737).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker:

  - to cause the client to spend an unreasonably long period of time generating a key for this prime resulting
  in a hang until the client has finished. This could be exploited in a Denial Of Service attack (CVE-2018-0732).

  - with sufficient access to mount cache timing attacks during the RSA key generation process could recover the
  private key (CVE-2018-0737).");

  script_tag(name:"affected", value:"OpenSSL 1.1.0-1.1.0h and 1.0.2-1.0.2o.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0i or 1.0.2p or
  later. See the references for more details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

if( version_in_range( version:vers, test_version:"1.0.2", test_version2:"1.0.2o" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.2p", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
