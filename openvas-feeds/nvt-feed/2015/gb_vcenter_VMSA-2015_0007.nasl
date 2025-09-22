# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vcenter_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105395");
  script_cve_id("CVE-2015-5177", "CVE-2015-2342", "CVE-2015-1047");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2024-06-28T15:38:46+0000");
  script_name("VMware vCenter Server Multiple Vulnerabilities (VMSA-2015-0007)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0007.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"- VMware vCenter Server JMX RMI Remote Code Execution:

  VMware vCenter Server contains a remotely accessible JMX RMI service that is not securely
  configured. An unauthenticated remote attacker that is able to connect to the service may be able
  use it to execute arbitrary code on the vCenter server.

  - VMware vCenter Server vpxd denial-of-service vulnerability:

  VMware vCenter Server does not properly sanitize long heartbeat messages. Exploitation of this
  issue may allow an unauthenticated attacker to create a denial-of-service condition in the vpxd
  service.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vCenter Server JMX RMI remote code execution (RCE) / vpxd
  denial of service (DoS) vulnerability");

  script_tag(name:"affected", value:"VMware vCenter Server 6.0 prior to version 6.0 update 1

  VMware vCenter Server 5.5 prior to version 5.5 update 3

  VMware vCenter Server 5.1 prior to version 5.1 update u3b

  VMware vCenter Server 5.0 prior to version 5.u update u3e");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-12 01:29:00 +0000 (Sun, 12 Aug 2018)");
  script_tag(name:"creation_date", value:"2015-10-05 11:16:27 +0200 (Mon, 05 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_vmware_vcenter_server_consolidation.nasl");
  script_mandatory_keys("vmware/vcenter/server/detected", "vmware/vcenter/server/build");

  exit(0);
}

include("host_details.inc");
include("vmware_esx.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vcenter/server/build" ) )
  exit( 0 );

fixed_builds = make_array( "5.0.0", "3073236",
                           "5.1.0", "3070521",
                           "5.5.0", "3000241",
                           "6.0.0", "3040890" );

if( ! fixed_builds[version] )
  exit( 0 );

if( int( build ) < int( fixed_builds[version] ) ) {
  security_message( port:0, data:esxi_remote_report( ver:version, build:build, fixed_build:fixed_builds[version], typ:"vCenter" ) );
  exit( 0 );
}

exit( 99 );