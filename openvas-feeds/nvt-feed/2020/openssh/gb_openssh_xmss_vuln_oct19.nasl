# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108729");
  script_version("2024-12-13T05:05:32+0000");
  script_cve_id("CVE-2019-16905");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-12-13 05:05:32 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-22 14:15:00 +0000 (Tue, 22 Oct 2019)");
  script_tag(name:"creation_date", value:"2020-03-23 08:47:12 +0000 (Mon, 23 Mar 2020)");
  script_name("OpenSSH 7.7 - 7.9, 8.x < 8.1 Integer Overflow Vulnerability");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-8.1");
  script_xref(name:"URL", value:"https://0day.life/exploits/0day-1009.html");
  script_xref(name:"URL", value:"https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sshkey-xmss.c.diff?r1=1.5&r2=1.6&f=h");

  script_tag(name:"summary", value:"OpenSSH is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An exploitable integer overflow bug was found in the private key
  parsing code for the XMSS key type. This key type is still experimental and support for it is not
  compiled by default. No user-facing autoconf option exists in portable OpenSSH to enable it.");

  script_tag(name:"impact", value:"Successfully exploitation could lead to memory corruption and
  local code execution.");

  script_tag(name:"affected", value:"OpenSSH versions 7.7 through 7.9 and 8.x before 8.1.");

  script_tag(name:"solution", value:"Update to version 8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  # nb: Experimental feature not enabled by default so an unreliable QoD is used for Windows-Based
  # systems as well.
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

if( vers =~ "^7\.[7-9]" || ( vers =~ "^8\." && version_is_less( version:vers, test_version:"8.1" ) ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
