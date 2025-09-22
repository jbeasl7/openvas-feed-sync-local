# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154746");
  script_version("2025-06-17T05:40:22+0000");
  script_tag(name:"last_modification", value:"2025-06-17 05:40:22 +0000 (Tue, 17 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-16 03:28:49 +0000 (Mon, 16 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-36631", "CVE-2025-36632", "CVE-2025-36633");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent Multiple Vulnerabilities (TNS-2025-11)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/win/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-36631: A non-administrative user could overwrite arbitrary local system files with log
  content at SYSTEM privilege

  - CVE-2025-36632: A non-administrative user could execute code with SYSTEM privilege

  - CVE-2025-36633: A non-administrative user could arbitrarily delete local system files with
  SYSTEM privilege, potentially leading to local privilege escalation");

  script_tag(name:"affected", value:"Tenable Nessus Agent prior to version 10.8.5 on Windows.");

  script_tag(name:"solution", value:"Update to version 10.8.5 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2025-11");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8.5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
