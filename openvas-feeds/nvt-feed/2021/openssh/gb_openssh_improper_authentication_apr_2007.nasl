# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150635");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2021-05-27 14:42:43 +0000 (Thu, 27 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2007-2243", "CVE-2007-2768");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSH < 4.7 Improper Authentication Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenSSH is prone to multiple improper authentication
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2007-2243: OpenSSH, when configured to use S/KEY
  authentication, is prone to a remote information disclosure weakness. The issue occurs due to the
  S/KEY challenge/response system being used for valid accounts. If a remote attacker systematically
  attempts authentication against a list of usernames, he can watch the response to determine which
  accounts are valid.

  If 'ChallengeResponseAuthentication' is set to 'Yes', which is the default setting, OpenSSH allows
  the user to login by using S/KEY in the form of 'ssh userid:skey at hostname'.

  - CVE-2007-2768: OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows
  remote attackers to determine the existence of certain user accounts, which displays a different
  response if the user account exists and is configured to use one-time passwords (OTP), a similar
  issue to CVE-2007-2243.");

  script_tag(name:"affected", value:"OpenSSH version 4.6 and prior.");

  script_tag(name:"solution", value:"Update to version 4.7 or later.");

  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2007040138");
  script_xref(name:"URL", value:"https://web.archive.org/web/20131127034915/http://archives.neohapsis.com:80/archives/fulldisclosure/2007-04/0590.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20140831195656/http://archives.neohapsis.com/archives/fulldisclosure/2007-04/0635.html");

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

if( version_is_less_equal(version:vers, test_version:"4.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.7", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
