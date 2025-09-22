# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154240");
  script_version("2025-03-28T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-03-28 05:39:44 +0000 (Fri, 28 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-27 04:17:57 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-30232");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim 4.96 < 4.98.2 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free is possible, with potential for privilege
  escalation.");

  script_tag(name:"affected", value:"Exim version 4.96 through 4.98.1.");

  script_tag(name:"solution", value:"Update to version 4.98.2 or later.");

  script_xref(name:"URL", value:"https://exim.org/static/doc/security/CVE-2025-30232.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "4.96", test_version_up: "4.98.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.98.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
