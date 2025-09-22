# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834644");
  script_version("2025-01-24T05:37:33+0000");
  script_cve_id("CVE-2024-9392", "CVE-2024-9393", "CVE-2024-9394", "CVE-2024-9401");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-11 16:08:21 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-03 11:47:49 +0530 (Thu, 03 Oct 2024)");
  script_name("Mozilla Firefox ESR Security Update (MFSA2024-48) - Windows");

  script_tag(name:"summary", value:"Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-9392: Compromised content process can bypass site isolation

  - CVE-2024-9393: Cross-origin access to PDF contents through multipart responses");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information and cause denial of service
  attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  115.16 and 128.x prior to 128.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 115.16 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-48/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.16")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.16", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);