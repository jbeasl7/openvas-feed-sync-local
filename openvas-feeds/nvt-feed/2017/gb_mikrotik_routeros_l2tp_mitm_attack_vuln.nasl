# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810609");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-03-09 16:21:26 +0530 (Thu, 09 Mar 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-6297");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS 'L2TP' Man-in-the-Middle Attack Vulnerability (Feb 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a man in the middle attack
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the L2TP client which does
  not enable IPsec encryption after a reboot.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view
  unencrypted transmitted data and gain access to networks on the L2TP server by monitoring the
  packets for the transmitted data and obtaining the L2TP secret.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions 6.83.3 and 6.37.4");

  script_tag(name:"solution", value:"Update to version 6.37.5, 6.83.4 or later.");

  script_xref(name:"URL", value:"https://blog.milne.it/2017/02/24/mikrotik-routeros-security-vulnerability-l2tp-tunnel-unencrypted-cve-2017-6297");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96447");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version =~ "^6\.") {
  if( version_is_equal( version:version, test_version:"6.83.3" ) ||
      version_is_equal( version:version, test_version:"6.37.4" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"6.37.5, 6.83.4 or later");
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
