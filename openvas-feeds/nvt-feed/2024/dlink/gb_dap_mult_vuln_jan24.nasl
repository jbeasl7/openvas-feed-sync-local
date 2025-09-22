# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dap-1650_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103789");
  script_version("2025-05-22T05:40:21+0000");
  script_tag(name:"last_modification", value:"2025-05-22 05:40:21 +0000 (Thu, 22 May 2025)");
  script_tag(name:"creation_date", value:"2024-07-19 08:51:39 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-31 21:06:08 +0000 (Wed, 31 Jan 2024)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2024-23624", "CVE-2024-23625");

  script_name("D-Link DAP-1650 EOL Device Multiple Command Injection Vulnerabilities (Jan 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"D-Link DAP-1650 devices are prone to multiple command injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is an End of Life (EOL) device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-23624: A command injection vulnerability exists in the gena.cgi module.

  - CVE-2024-23625: A command injection vulnerability exists when handling UPnP SUBSCRIBE
  messages.");

  script_tag(name:"affected", value:"D-Link DAP-1650 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that the model reached its End-of-Support Date, it is no longer supported, and
  firmware development has ceased. See vendor advisory for further recommendations.");

  script_xref(name:"URL", value:"https://blog.exodusintel.com/2024/01/25/d-link-dap-1650-gena-cgi-subscribe-command-injection-vulnerability/");
  script_xref(name:"URL", value:"https://blog.exodusintel.com/2024/01/25/d-link-dap-1650-subscribe-callback-command-injection-vulnerability/");
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
