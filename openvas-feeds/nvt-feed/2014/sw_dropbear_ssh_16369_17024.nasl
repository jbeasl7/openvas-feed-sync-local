# SPDX-FileCopyrightText: 2014 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105118");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-11-14 12:00:00 +0100 (Fri, 14 Nov 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2006-0225", "CVE-2006-1206");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dropbear < 0.48 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 SCHUTZWERK GmbH");
  script_family("General");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_tag(name:"summary", value:"Dropbear is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - CVE-2006-1206: A large number of connection attempts that exceeds the MAX_UNAUTH_CLIENTS defined
  value of 30 is possible.

  - CVE-2006-0225: The shipped scp command of OpenSSH 4.2p1 expands filenames that contain shell
  metacharacters or spaces twice which also affects Dropbear");

  script_tag(name:"impact", value:"The flaws allows remote attackers to cause a denial of service
  (connection slot exhaustion) and local attackers to execute arbitrary commands.");

  script_tag(name:"affected", value:"Dropbear versions prior to 0.48.");

  script_tag(name:"solution", value:"Update to version 0.48 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210217161602/http://www.securityfocus.com/bid/17024");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210201155148/http://www.securityfocus.com/bid/16369");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/1572");
  script_xref(name:"URL", value:"https://matt.ucc.asn.au/dropbear/CHANGES");

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

ver = eregmatch( pattern:"^([0-9]+)\.([0-9]+)", string:vers );

if( isnull( ver[2] ) ) exit( 0 );

if( int( ver[1] ) > 0 ) exit( 99 );

if( version_is_less( version:ver[2], test_version:"48" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.48", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
