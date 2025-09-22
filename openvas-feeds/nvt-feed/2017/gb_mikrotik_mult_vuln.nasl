# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113068");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-12-14 12:11:10 +0100 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-17538", "CVE-2017-17537");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MikroTik RouterOS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MicroTik RouterOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities allow for two ways of causing an denial of
  service (DoS):

  - An attacker can flood the device with ICMP packets

  - An attacker can connect to TCP-port 53 and send data starting with a lot of Null-Byte
  characters, probably related to DNS.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to make the
  device unavailable.");

  script_tag(name:"affected", value:"MikroTik Router OS version 6.40.5 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/current-release-tree");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe: CPE , nofork: TRUE ) )
  exit( 0 );

if( version_is_less_equal( version: version, test_version: "6.40.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 0 );
