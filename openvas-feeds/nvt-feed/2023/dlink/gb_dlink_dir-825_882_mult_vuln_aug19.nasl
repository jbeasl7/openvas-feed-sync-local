# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170304");
  script_version("2024-08-14T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-08-14 05:05:52 +0000 (Wed, 14 Aug 2024)");
  script_tag(name:"creation_date", value:"2023-02-04 21:45:34 +0000 (Sat, 04 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-27 14:29:00 +0000 (Thu, 27 Apr 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-13263", "CVE-2019-13264", "CVE-2019-13265");

  script_name("D-Link DIR-825 Rev G1 <= 1.04Beta, DIR-882 Rev A1 <= 1.30b06Beta Multiple Router Isolation Bypass Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-825 and DIR-882 devices are prone to multiple router
  isolation bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following router isolation bypass vulnerabilities exist:

  - CVE-2019-13263: DHCP attack

  - CVE-2019-13264: IGMP attack

  - CVE-2019-13265: ARP attack");

  script_tag(name:"affected", value:"D-Link DIR-825 Rev G1 prior to firmware version 2.06b01
  and DIR-882 Rev A1 prior to 1.30b06Beta.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10121");
  script_xref(name:"URL", value:"https://www.usenix.org/system/files/woot19-paper_ovadia.pdf");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dlink:dir-825_firmware",
                      "cpe:/o:dlink:dir-882_firmware" );

if ( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = infos["version"];

if ( ! hw_version = get_kb_item( "d-link/dap/hw_version" ) )
  exit( 0 );

#nb: The advisory makes reference to "All HW Rev Gx"
if ( cpe == "cpe:/o:dlink:dir-825_firmware" ) {
  if ( hw_version =~ "G" && ( revcomp( a:version, b:"1.04Beta" ) < 0 ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.04Beta", extra:"Hardware revision: " + hw_version );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "cpe:/o:dlink:dir-882_firmware" ) {
  if ( hw_version =~ "A" && ( revcomp( a:version, b:"1.30b06Beta" ) < 0 ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"1.30b06Beta", extra:"Hardware revision: " + hw_version );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
