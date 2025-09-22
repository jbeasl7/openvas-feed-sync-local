# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dap-1522_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170478");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2023-05-23 09:03:02 +0000 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 02:55:00 +0000 (Thu, 26 May 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2015-2051", "CVE-2018-6530", "CVE-2022-26258");

  script_name("D-Link DAP-1522 Devices Multiple Vulnerabilities (Sep 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"D-Link DAP-1522 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The Mirai BotNet variant MooBot leverages several
  vulnerabilities to compromise D-Link devices.

  Note: This VT initially also included CVE-2022-28958 but as described in the references it turned
  out to be an invalid vulnerability which doesn't exist.");

  script_tag(name:"affected", value:"D-Link DAP-1522 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DAP-1522 devices reached their End-of-Support Date, they are no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10302");
  script_xref(name:"URL", value:"https://unit42.paloaltonetworks.com/moobot-d-link-devices/");
  script_xref(name:"URL", value:"https://vulncheck.com/blog/moobot-uses-fake-vulnerability");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
