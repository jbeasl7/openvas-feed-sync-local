# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dap-1650_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103796");
  script_version("2025-05-22T05:40:21+0000");
  script_tag(name:"last_modification", value:"2025-05-22 05:40:21 +0000 (Thu, 22 May 2025)");
  script_tag(name:"creation_date", value:"2024-07-19 10:15:28 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2024-40505");

  script_name("D-Link DAP-1650 EOL Device Directory Traversal Vulnerability (Jul 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"D-Link DAP-1650 devices are prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is an End of Life (EOL) device.");

  script_tag(name:"insight", value:"A directory traversal vulnerability exists in D-Link DAP-1650
  firmware that allows a local attacker to escalate privileges via the hedwig.cgi component.");

  script_tag(name:"affected", value:"D-Link DAP-1650 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that the model reached its End-of-Support Date, it is no longer supported, and
  firmware development has ceased. See vendor advisory for further recommendations.");

  script_xref(name:"URL", value:"https://coldwx.github.io/CVE-2024-40505.html");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10266");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# EoL, all versions affected
report = report_fixed_ver(installed_version: version, fixed_version: "None");
security_message(port: 0, data: report);
exit(0);
