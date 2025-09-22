# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807574");
  script_version("2024-12-13T05:05:32+0000");
  script_cve_id("CVE-2015-8325");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-13 05:05:32 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-30 01:29:00 +0000 (Sat, 30 Jun 2018)");
  script_tag(name:"creation_date", value:"2016-05-02 15:45:55 +0530 (Mon, 02 May 2016)");
  script_name("OpenSSH <= 7.2p2 Privilege Escalation Vulnerability (May 2016)");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"https://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-8325.html");
  script_xref(name:"URL", value:"https://anongit.mindrot.org/openssh.git/commit/?id=85bdcd7c92fe7ff133bbc4e10a65c91810f88755");

  script_tag(name:"summary", value:"OpenSSH is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'do_setup_env function' in
  the 'session.c' script in sshd which trigger a crafted environment for the /bin/login program when
  the UseLogin feature is enabled and PAM is configured to read .pam_environment files in user home
  directories.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow local users to gain
  privileges.");

  script_tag(name:"affected", value:"OpenSSH versions through 7.2p2.");

  script_tag(name:"solution", value:"Update to version 7.2p2-3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if( vers =~ "^[0-6]\." || vers =~ "^7\.[01]($|[^0-9])" || vers =~ "^7\.2($|p1|p2)" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.2p2-3", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
