# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818505");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2021-29981", "CVE-2021-29988", "CVE-2021-29984", "CVE-2021-29980",
                "CVE-2021-29985", "CVE-2021-29982", "CVE-2021-29989");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-25 02:08:00 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-17 00:33:02 +0530 (Tue, 17 Aug 2021)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2021-35, MFSA2021-36) - Windows");

  script_tag(name:"summary", value:"This host is missing a security update
  according to Mozilla.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Live range splitting could have led to conflicting assignments in the JIT.

  - Memory corruption as a result of incorrect style treatment.

  - Incorrect instruction reordering during JIT optimization.

  - Uninitialized memory in a canvas object could have led to memory corruption.

  - Use-after-free media channels.

  - Single bit data leak due to incorrect JIT optimization and type confusion.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, disclose sensitive
  information and cause a denial of service on affected system");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  91 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 91
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-36/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"91")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"91", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
