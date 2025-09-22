# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802407");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2002-0640");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-07 18:20:44 +0530 (Wed, 07 Dec 2011)");
  script_name("OpenSSH 'sshd' Challenge Response Authentication Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/369347");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5093");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-18.html");
  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=102521542826833&w=2");

  script_tag(name:"summary", value:"OpenSSH sshd with ChallengeResponseAuthentication enabled is prone to a buffer overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to execute arbitrary
  code and gain escalated privileges.");

  script_tag(name:"affected", value:"OpenSSH versions 2.3.1 to 3.3.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling a large number of responses
  during challenge response authentication when using PAM modules with
  interactive keyboard authentication (PAMAuthenticationViaKbdInt).");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 3.4 or later.");

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

if( version_in_range( version:vers, test_version:"2.3.1", test_version2:"3.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.4", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );