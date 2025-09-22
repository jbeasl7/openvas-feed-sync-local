# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902488");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2005-2798");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-11-16 12:24:22 +0530 (Wed, 16 Nov 2011)");
  script_name("OpenSSH 'sshd' GSSAPI Credential Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/16686");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14729");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1014845");
  script_xref(name:"URL", value:"https://lists.mindrot.org/pipermail/openssh-unix-announce/2005-September/000083.html");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass security
  restrictions and gain escalated privileges.");

  script_tag(name:"affected", value:"OpenSSH version prior to 4.2.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling GSSAPI credential delegation,
  Which allow GSSAPI credentials to be delegated to users who log in with methods other than GSSAPI authentication
  (e.g. public key) when the client requests it.");

  script_tag(name:"solution", value:"Upgrade OpenSSH to 4.2 or later.");

  script_tag(name:"summary", value:"OpenSSH sshd with GSSAPI enabled is prone to credential disclosure vulnerability.");

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

if( version_is_less( version:vers, test_version:"4.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );