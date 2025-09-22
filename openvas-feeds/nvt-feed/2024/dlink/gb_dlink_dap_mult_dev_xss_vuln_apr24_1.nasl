# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170776");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-04-29 19:10:27 +0000 (Mon, 29 Apr 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2024-28436");

  script_name("D-Link Multiple EOL DAP Devices XSS Vulnerability (Apr 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"Multiple D-Link DAP devices are prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The vulnerability was identified in the 'reload' parameter of
  the '/session_login.php' page, a critical component used for user authentication and session
  management across the affected DAP products.");

  script_tag(name:"affected", value:"D-Link DAP-2330, DAP-2553, DAP-2565, DAP-2590, DAP-2660,
  DAP-2690, DAP-2695, DAP-3520 and DAP-3662 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that all models reached their End-of-Support Date, they are no longer
  supported, and firmware development has ceased. Please see the vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://djallalakira.medium.com/cve-2024-28436-cross-site-scripting-vulnerability-in-d-link-dap-products-3596976cc99f");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10380");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dlink:dap-2330_firmware",
                      "cpe:/o:dlink:dap-2553_firmware",
                      "cpe:/o:dlink:dap-2565_firmware",
                      "cpe:/o:dlink:dap-2590_firmware",
                      "cpe:/o:dlink:dap-2660_firmware",
                      "cpe:/o:dlink:dap-2690_firmware",
                      "cpe:/o:dlink:dap-2695_firmware",
                      "cpe:/o:dlink:dap-3520_firmware",
                      "cpe:/o:dlink:dap-3662_firmware" );

if ( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

version = infos["version"];

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
