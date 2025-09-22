# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:axis:207w_firmware";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170347");
  script_version("2023-10-24T05:06:28+0000");
  script_tag(name:"last_modification", value:"2023-10-24 05:06:28 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-07 09:02:07 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-02 16:24:00 +0000 (Thu, 02 Mar 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2023-22984");

  script_name("AXIS 207W Network Camera XSS Vulnerability (Feb 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"AXIS 207W network camera devices are prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a reflected XSS vulnerability in the web administration
  portal, which allows an attacker to execute arbitrary JavaScript via URL.");

  script_tag(name:"affected", value:"AXIS 207W Network Camera devices, all versions");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The vendor states that technical support for 207W has ended in 28.02.2014, therefore most
  probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://d0ub1e-d.github.io/2022/12/30/exploit-db-1/");
  script_xref(name:"URL", value:"https://www.axis.com/products/axis-207w/support");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version: version, fixed_version: "None" );
security_message( data: report, port: 0 );
exit( 0 );

