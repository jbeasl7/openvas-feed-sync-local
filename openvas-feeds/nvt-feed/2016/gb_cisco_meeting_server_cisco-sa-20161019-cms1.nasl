# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:meeting_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140045");
  script_cve_id("CVE-2016-6446");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Meeting Server Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161019-cms1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in Web Bridge for Cisco Meeting Server could allow an unauthenticated, remote
attacker to retrieve memory from a connected server.

The vulnerability is due to missing bounds checks in the Web Bridge functionality. An attacker could
exploit this vulnerability by sending a crafted packet to the affected server. An exploit could
allow the attacker to disclose a portion of memory from the server for every packet. The disclosed
portions of memory could contain sensitive information such as private keys or passwords.

Cisco has released software updates that address this vulnerability. Workarounds that address this
vulnerability are not available.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:32:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-11-02 16:19:35 +0100 (Wed, 02 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_meeting_server_snmp_detect.nasl");
  script_mandatory_keys("cisco/meeting_server/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '1.8.0',
  '1.8.15',
  '1.9.0',
  '1.9.2',
  '2.0.0',
  '2.0.1',
  '2.0.3',
  '2.0.4',
  '2.0.5' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

