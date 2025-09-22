# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:spring_boot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113881");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-04-06 08:06:40 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("VMware Spring Boot End of Life (EOL) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_spring_boot_consolidation.nasl");
  script_mandatory_keys("vmware/spring/boot/detected");

  script_xref(name:"URL", value:"https://spring.io/projects/spring-boot#support");
  script_xref(name:"URL", value:"https://github.com/spring-projects/spring-boot/wiki/Supported-Versions");

  script_tag(name:"summary", value:"The VMware Spring Boot version on the remote host has
  reached the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of VMware Spring Boot is not receiving any
  security updates from the vendor. Unfixed security vulnerabilities might be leveraged by an
  attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the VMware Spring Boot version on the remote host
  to a still supported version.

  Note / important: The EOL dates are currently defined as the 'End of OSS Support' listed in the
  reference. If the version on the target is covered by Enterprise Support and the EOL for that
  version hasn't reached the EOL date yet please create an override for this result.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

ver = infos["version"];

if( ret = product_reached_eol( cpe:CPE, version:ver ) ) {
  report = eol_build_message( name:"VMware Spring Boot",
                              cpe:CPE,
                              version:ver,
                              location:infos["location"],
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
