# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-825_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170308");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2023-02-14 14:50:15 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 16:28:00 +0000 (Tue, 17 Aug 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2021-29296");

  script_name("D-Link DIR-825 Rev B <= 2.10b02 NULL Pointer Dereference Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-825 Rev. B devices are prone to a NULL pointer
  dereference vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability could be triggered by sending HTTP request with
  URL /vct_wan. Thus, the sbin/httpd would invoke the strchr function and take NULL as a first
  argument, which finally leads to the segmentation fault.");

  script_tag(name:"impact", value:"The vulnerability could let a remote malicious user cause a
  denial of service.");

  script_tag(name:"affected", value:"D-Link DIR-825 Rev B devices through firmware version 2.10b02.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  The DIR-825 revision B model has entered the end-of-life process by the time these vulnerabilities
  were disclosed and therefore the vendor is unable to provide support or development to mitigate
  them.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10212");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( ! hw_version = get_kb_item( "d-link/dir/hw_version" ) )
  exit( 0 );

if ( hw_version =~ "B" && ( revcomp( a:version, b:"2.10b2" ) <= 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location, extra:"Hardware revision: " + hw_version );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
