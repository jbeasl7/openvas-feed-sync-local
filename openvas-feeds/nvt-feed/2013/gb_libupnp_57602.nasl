# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libupnp_project:libupnp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103658");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2012-5958", "CVE-2012-5959", "CVE-2012-5960",
                "CVE-2012-5961", "CVE-2012-5962", "CVE-2012-5963",
                "CVE-2012-5964", "CVE-2012-5965");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-06 15:35:24 +0100 (Wed, 06 Feb 2013)");
  script_name("libupnp Multiple Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_libupnp_consolidation.nasl");
  script_mandatory_keys("libupnp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57602");

  script_tag(name:"solution", value:"libupnp is prone to multiple buffer-overflow vulnerabilities because
  it fails to perform adequate boundary checks on user-supplied data.");
  script_tag(name:"summary", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code in the
  context of the device that uses the affected library. Failed exploit
  attempts will likely crash the application.");
  script_tag(name:"affected", value:"libupnp versions prior to 1.6.18 are affected.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"1.6.18" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.18" );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
