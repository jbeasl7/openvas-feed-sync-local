# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vrealize_operations_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140063");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-11-16 15:53:11 +0100 (Wed, 16 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");

  script_cve_id("CVE-2016-7462");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware vRealize Operations REST API Deserialization Vulnerability (VMSA-2016-0020)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_vrealize_operations_manager_http_detect.nasl");
  script_mandatory_keys("vmware/vrealize/operations_manager/detected");

  script_tag(name:"summary", value:"VMware vRealize Operations is prone to a deserialization
  vulnerability in its REST API implementation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This issue may result in a denial of service as it allows for
  writing of files with arbitrary content and moving existing files into certain folders. The name
  format of the destination files is predefined and their names cannot be chosen. Overwriting files
  is not feasible.");

  script_tag(name:"affected", value:"VMware vRealize Operations version 6.x prior to 6.4.0.");

  script_tag(name:"solution", value:"Update to version 6.4.0 or later.");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0020.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range_exclusive( version:version, test_version_lo: "6.0.0", test_version_up: "6.4.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.4.0" );
  security_message( port:port, data:report );
  exit(0);
}

exit( 99 );
