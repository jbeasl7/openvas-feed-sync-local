# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103247");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2001-0572");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-09 13:52:42 +0200 (Fri, 09 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OpenSSH Ciphersuite Specification Information Disclosure Weakness");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49473");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/596827");

  script_tag(name:"impact", value:"Successfully exploiting this issue in conjunction with other latent
  vulnerabilities may allow attackers to gain access to sensitive information that
  may aid in further attacks.");

  script_tag(name:"affected", value:"Releases prior to OpenSSH 2.9p2 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"OpenSSH is prone to a security weakness that may allow attackers to
  downgrade the ciphersuite.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"2.9p2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.9p2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );