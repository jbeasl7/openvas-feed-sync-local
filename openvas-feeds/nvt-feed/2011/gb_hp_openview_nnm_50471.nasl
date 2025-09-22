# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103364");
  script_cve_id("CVE-2011-3166", "CVE-2011-3167");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2024-06-28T05:05:33+0000");
  script_name("HP OpenView Network Node Manager Multiple RCE Vulnerabilities");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-12-14 09:14:18 +0100 (Wed, 14 Dec 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  script_mandatory_keys("HP/OVNNM/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520349");

  script_tag(name:"summary", value:"HP OpenView Network Node Manager (NNM) is prone to multiple remote
  code-execution vulnerabilities because it fails to sanitize user-supplied data.");
  script_tag(name:"affected", value:"These issues affects NNM 7.51, v7.53 running on HP-UX, Linux, Solaris,
  and Windows. Other versions and platforms may also be affected.");
  script_tag(name:"solution", value:"Updates are available.Please contact the vendor for more information.");
  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code with
  the privileges of the user running the affected application.
  Successful exploits will compromise the affected application and
  possibly the underlying computer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_version( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! vers = get_kb_item( "www/"+ port + "/HP/OVNNM/Ver" ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
