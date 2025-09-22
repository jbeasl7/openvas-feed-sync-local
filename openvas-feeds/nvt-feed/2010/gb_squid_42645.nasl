# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100774");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2951");
  script_name("Squid 3.1.6 'DNS' Reply Remote Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42645");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=62692");
  script_xref(name:"URL", value:"http://marc.info/?l=squid-users&m=128263555724981&w=2");

  script_tag(name:"affected", value:"Squid version 3.1.6 is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code
  within the context of the affected application. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Squid is prone to a remote buffer-overflow vulnerability
  because it fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"3.1.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.7" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
