# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dap-1513_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171031");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-12-23 10:35:50 +0000 (Mon, 23 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2024-36832");

  script_name("D-Link DAP-1513 Multiple Vulnerabilities (Nov 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"D-Link DAP-1513 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-36832: When /bin/webs receives a carefully constructed HTTP request, it will crash and
  exit due to a null pointer reference.

  - No CVE: Multiple NULL dereference and stack buffer overflows in /bin/webs

  - No CVE: Buffer overflow at memcpy() in process_request() in /bin/webs");

  script_tag(name:"affected", value:"D-Link DAP-1513 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DAP-1513 model reached its End-of-Support Date in 13.01.2018, it is no
  longer supported, and firmware development has ceased. It is recommended to replace the device
  with a newer model.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10396");
  script_xref(name:"URL", value:"https://docs.google.com/document/d/1qTpwAg7B5E4mqkBzijjuoOWWnf3OE1HXIKBv7OcS8Mc/edit?tab=t.0#heading=h.bx931c9pkeoj");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10338");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10313");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
