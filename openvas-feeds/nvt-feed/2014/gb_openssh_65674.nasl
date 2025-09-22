# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105002");
  script_cve_id("CVE-2011-4327");
  script_version("2025-01-17T15:39:18+0000");
  script_name("OpenSSH 'ssh-keysign.c' Local Information Disclosure Vulnerability");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-04-09 12:29:38 +0200 (Wed, 09 Apr 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65674");
  script_xref(name:"URL", value:"http://www.openssh.com/txt/portable-keysign-rand-helper.adv");

  script_tag(name:"impact", value:"Local attackers can exploit this issue to obtain sensitive
  information. Information obtained may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ssh-keysign.c in ssh-keysign in OpenSSH before 5.8p2 on
  certain platforms executes ssh-rand-helper with unintended open file descriptors, which allows
  local users to obtain sensitive key information via the ptrace system call.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"OpenSSH is prone to a local information disclosure vulnerability.");

  script_tag(name:"affected", value:"Versions prior to OpenSSH 5.8p2 are vulnerable.");

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

if( version_is_less( version:vers, test_version:"5.8p2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.8p2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
