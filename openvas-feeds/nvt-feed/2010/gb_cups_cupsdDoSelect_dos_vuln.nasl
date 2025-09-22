# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800487");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:22:17 +0000 (Sat, 03 Feb 2024)");

  script_cve_id("CVE-2010-0302");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS 1.3.x, 1.4.x < 1.4.4 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) service is prone to a denial
  of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an use-after-free error within the
  'cupsdDoSelect()' function in 'scheduler/select.c' when kqueue or epoll is used, allows remote
  attackers to crash or hang the daemon via a client disconnection during listing of a large number
  of print jobs.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code and can cause denial of service.");

  script_tag(name:"affected", value:"CUPS versions 1.3.x and 1.4.x prior to 1.4.x.");

  script_tag(name:"solution", value:"Update to version 1.4.4 or later.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-906-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38510");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2010-0129.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=557775");
  script_xref(name:"URL", value:"https://github.com/apple/cups/issues/3490");
  script_xref(name:"URL", value:"https://github.com/apple/cups/releases/tag/release-1.4.4");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+")
  exit( 0 ); # Version is not exact enough

if( version_in_range( version:vers, test_version:"1.3.0", test_version2:"1.4.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
