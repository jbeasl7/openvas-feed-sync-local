# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834986");
  script_version("2025-03-06T05:38:27+0000");
  script_cve_id("CVE-2025-22224", "CVE-2025-22226");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-05 16:18:36 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-05 12:08:45 +0530 (Wed, 05 Mar 2025)");
  script_name("VMware Workstation Multiple Vulnerabilities (VMSA-2025-0004) - Linux");

  script_tag(name:"summary", value:"VMware Workstation is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2025-22224: VMCI heap-overflow vulnerability

  - CVE-2025-22226: HGFS information-disclosure vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code and disclose sensitive information.");

  script_tag(name:"affected", value:"VMware Workstation 17.x before 17.6.3 on
  Linux.");

  script_tag(name:"solution", value:"Update to version 17.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed", "VMware/Workstation/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^17\." && version_is_less(version:vers, test_version:"17.6.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.6.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);