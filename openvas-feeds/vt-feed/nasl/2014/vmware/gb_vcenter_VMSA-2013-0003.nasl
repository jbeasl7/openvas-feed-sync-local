# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vcenter_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103874");
  script_cve_id("CVE-2013-1659");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_version("2026-04-28T06:28:06+0000");
  script_name("VMware Security Updates for vCenter Server (VMSA-2013-0003)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0003.html");

  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2014-01-09 13:04:01 +0100 (Thu, 09 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vmware_vcenter_server_consolidation.nasl");
  script_mandatory_keys("vmware/vcenter/server/detected", "vmware/vcenter/server/build");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"VMware vCenter, ESXi and ESX NFC protocol memory corruption
  vulnerability.

  VMware vCenter Server, ESXi and ESX contain a vulnerability in the handling of the Network File
  Copy (NFC) protocol. To exploit this vulnerability, an attacker must intercept and modify the NFC
  traffic between vCenter Server and the client or ESXi/ESX and the client. Exploitation of the
  issue may lead to code execution.

  To reduce the likelihood of exploitation, vSphere components should be deployed on an isolated
  management network.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"VMware has updated VMware vCenter Server to address a
  vulnerability in the Network File Copy (NFC) Protocol.");

  script_tag(name:"affected", value:"- VMware vCenter Server 5.1 prior to 5.1.0b

  - VMware vCenter Server 5.0 prior to 5.0 Update 2");

  exit(0);
}

include("host_details.inc");
include("vmware_esx.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vcenter/server/build" ) )
  exit( 0 );

fixed_builds = make_array( "5.0.0", "913577",
                           "5.1.0", "947673" );

if( ! fixed_builds[version] )
  exit( 0 );

if( int( build ) < int( fixed_builds[version] ) ) {
  security_message( port:0, data:esxi_remote_report( ver:version, build:build, fixed_build:fixed_builds[version], typ:"vCenter" ) );
  exit( 0 );
}

exit( 99 );