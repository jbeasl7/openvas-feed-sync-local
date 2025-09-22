# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813550");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12372", "CVE-2018-12373",
                "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365",
                "CVE-2018-12366", "CVE-2018-12368", "CVE-2018-12374", "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-07-04 12:05:34 +0530 (Wed, 04 Jul 2018)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2018-14, MFSA2018-18) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to -

  - Buffer overflow error while using computed size of canvas element.

  - Use-after-free error when using focus()

  - Allowing S/MIME and PGP decryption oracles to be built with HTML emails.

  - S/MIME plaintext can be leaked through HTML reply/forward.

  - Integer overflow error in SSSE3 scaler.

  - Use-after-free error when appending DOM nodes.

  - CSRF vulnerabilities in 307 redirects and NPAPI.

  - Compromised IPC child process can list local filenames.

  - Invalid data handling during QCMS transformations.

  - No warning when opening executable SettingContent-ms files.

  - Using form to exfiltrate encrypted mail part by pressing enter in form field.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to crash the application, leak plaintext, perform cross-site request forgery
  attacks, expose of private local files, leak private data into the output and
  execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird versions before 52.9.");

  script_tag(name:"solution", value:"Update to version 52.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-18");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"52.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"52.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
