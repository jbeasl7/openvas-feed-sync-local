# SPDX-FileCopyrightText: 2014 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105114");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-11-07 12:40:00 +0100 (Fri, 07 Nov 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2013-4421", "CVE-2013-4434");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dropbear < 2013.59 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 SCHUTZWERK GmbH");
  script_family("General");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_tag(name:"summary", value:"Dropbear is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - CVE-2013-4421: The buf_decompress function in packet.c allows remote attackers to cause a
  denial-of-service (memory consumption) via a compressed packet that has a large size when it is
  decompressed.

  - CVE-2013-4434: The product generates error messages for a failed logon attempt with different
  time delays depending on whether the user account exists.");

  script_tag(name:"impact", value:"The flaws allows remote attackers to cause a denial-of-service
  or to discover valid usernames.");

  script_tag(name:"affected", value:"Dropbear versions prior to 2013.59.");

  script_tag(name:"solution", value:"Update to version 2013.59 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210120111858/http://www.securityfocus.com/bid/62958");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210120111952/http://www.securityfocus.com/bid/62993");
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

if( int( ver[1] ) > 2013 ) exit( 99 );

if(version_is_less(version:ver[2], test_version:"59")) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2013.59", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
