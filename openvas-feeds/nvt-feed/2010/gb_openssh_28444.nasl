# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100584");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2008-1483");
  script_name("OpenSSH X Connections Session Hijacking Vulnerability");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28444");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3137");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata41.html");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata42.html");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata43.html");
  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-5.0");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=590180");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=463011");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/492447");
  script_xref(name:"URL", value:"http://aix.software.ibm.com/aix/efixes/security/ssh_advisory.asc");
  script_xref(name:"URL", value:"http://support.avaya.com/elmodocs2/security/ASA-2008-205.htm");
  script_xref(name:"URL", value:"http://www.globus.org/mail_archive/security-announce/2008/04/msg00000.html");
  script_xref(name:"URL", value:"http://support.attachmate.com/techdocs/2374.html#Security_Updates_in_7.0_SP1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-237444-1");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker run arbitrary
  shell commands with the privileges of the user running the affected application.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"OpenSSH is prone to a vulnerability that allows attackers to hijack
  forwarded X connections.");

  script_tag(name:"affected", value:"This issue affects OpenSSH 4.3p2. Other versions may also be affected.

  NOTE: This issue affects the portable version of OpenSSH and may not
  affect OpenSSH running on OpenBSD.");

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

if( version_is_less( version:vers, test_version:"4.3p2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.3p2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );