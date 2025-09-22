# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806671");
  script_version("2024-12-13T05:05:32+0000");
  script_cve_id("CVE-2016-1907");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-12-13 05:05:32 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-17 02:59:00 +0000 (Fri, 17 Feb 2017)");
  script_tag(name:"creation_date", value:"2016-01-28 12:15:36 +0530 (Thu, 28 Jan 2016)");
  script_name("OpenSSH < 7.1p2 DoS Vulnerability (Jan 2016)");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-7.1p2");
  script_xref(name:"URL", value:"https://anongit.mindrot.org/openssh.git/commit/?id=2fecfd486bdba9f51b3a789277bb0733ca36e1c0");

  script_tag(name:"summary", value:"OpenSSH is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the 'ssh_packet_read_poll2'
  function within the 'packet.c' file.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to
  cause a denial of service (out-of-bounds read and application crash).");

  script_tag(name:"affected", value:"OpenSSH versions before 7.1p2.");

  script_tag(name:"solution", value:"Update to version 7.1p2 or later.");

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

if( version_is_less( version:vers, test_version:"7.1p2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.1p2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
