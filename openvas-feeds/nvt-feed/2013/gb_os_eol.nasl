# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103674");
  script_version("2025-05-21T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-21 05:40:19 +0000 (Wed, 21 May 2025)");
  script_tag(name:"creation_date", value:"2013-03-05 18:11:24 +0100 (Tue, 05 Mar 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Operating System (OS) End of Life (EOL) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("os_detection.nasl");
  script_mandatory_keys("HostDetails/OS/BestMatchCPE");

  script_tag(name:"summary", value:"The Operating System (OS) on the remote host has reached the end
  of life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version of an OS is present on the target
  host.");

  script_tag(name:"impact", value:"An EOL version of an OS is not receiving any security updates
  from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise
  the security of this host.");

  script_tag(name:"solution", value:"Update the OS on the remote host to a version which is still
  supported and receiving security updates by the vendor.

  Note / Important: Please create an override for this result if the target host is a:

  - Windows system with Extended Security Updates (ESU)

  - System with additional 3rd-party / non-vendor security updates like e.g. from 'TuxCare',
  'Freexian Extended LTS' or similar");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("eol_os.inc");
include("host_details.inc");
include("os_func.inc");
include("date_func.inc");
include("eol_shared.inc");
include("list_array_func.inc");

if( ! os_cpe = os_get_best_cpe() )
  exit( 0 );

if( os_reached_eol( cpe:os_cpe ) ) {

  # Store link between os_detection.nasl and gb_os_eol.nasl
  # nb: We don't use the host_details.inc functions in both so we need to call this directly.
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.105937" ); # os_detection.nasl
  register_host_detail( name:"detected_at", value:"general/tcp" ); # os_detection.nasl is using port:0

  eol_url     = get_eol_url( cpe:os_cpe );
  eol_date    = get_eol_date( cpe:os_cpe );
  eol_name    = get_eol_name( cpe:os_cpe );
  eol_version = get_eol_version( cpe:os_cpe );
  version     = get_version_from_cpe( cpe:os_cpe );

  report = eol_build_message( name:eol_name,
                              cpe:os_cpe,
                              version:version,
                              eol_version:eol_version,
                              eol_date:eol_date,
                              eol_url:eol_url,
                              eol_type:"os" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
