# SPDX-FileCopyrightText: 2002 Thomas Reinke
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10883");
  script_version("2024-02-02T05:06:11+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4241");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:11 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:52:51 +0000 (Fri, 02 Feb 2024)");
  script_cve_id("CVE-2002-0083");
  script_name("OpenSSH Channel Code Off by 1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Thomas Reinke");
  script_family("Gain a shell remotely");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"solution", value:"Upgrade to OpenSSH 3.1 or apply the patch for
  prior versions.");

  script_tag(name:"summary", value:"You are running a version of OpenSSH which is older than 3.1.");

  script_tag(name:"insight", value:"Versions prior than 3.1 are vulnerable to an off by one error
  that allows local users to gain root access, and it may be possible for remote users to similarly
  compromise the daemon for remote access.

  In addition, a vulnerable SSH client may be compromised by connecting to a malicious SSH daemon that
  exploits this vulnerability in the client code, thus compromising the client system.");

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

if( version_is_less( version:vers, test_version:"3.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );