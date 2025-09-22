# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832337");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-38580", "CVE-2023-36862", "CVE-2023-32364", "CVE-2023-35983",
                "CVE-2023-28319", "CVE-2023-28320", "CVE-2023-28321", "CVE-2023-28322",
                "CVE-2023-32416", "CVE-2023-32418", "CVE-2023-36854", "CVE-2023-32734",
                "CVE-2023-32441", "CVE-2023-38261", "CVE-2023-38424", "CVE-2023-38425",
                "CVE-2023-32381", "CVE-2023-32433", "CVE-2023-35993", "CVE-2023-38410",
                "CVE-2023-38606", "CVE-2023-38603", "CVE-2023-38565", "CVE-2023-38593",
                "CVE-2023-38258", "CVE-2023-38421", "CVE-2023-2953", "CVE-2023-38259",
                "CVE-2023-38564", "CVE-2023-38602", "CVE-2023-32442", "CVE-2023-32443",
                "CVE-2023-32429", "CVE-2023-38608", "CVE-2023-38572", "CVE-2023-38594",
                "CVE-2023-38595", "CVE-2023-38600", "CVE-2023-38611", "CVE-2023-37450",
                "CVE-2023-38597", "CVE-2023-38133", "CVE-2023-38616", "CVE-2023-34425",
                "CVE-2023-40392", "CVE-2023-34241", "CVE-2022-3970", "CVE-2023-28200",
                "CVE-2023-38590", "CVE-2023-38598", "CVE-2023-36495", "CVE-2023-37285",
                "CVE-2023-38604", "CVE-2023-38571", "CVE-2023-29491", "CVE-2023-38601",
                "CVE-2023-32444", "CVE-2023-38609", "CVE-2023-32654", "CVE-2023-38605",
                "CVE-2023-40397", "CVE-2023-38599", "CVE-2023-32445", "CVE-2023-38592",
                "CVE-2023-40437", "CVE-2023-40439", "CVE-2023-42828", "CVE-2023-42866",
                "CVE-2023-40440", "CVE-2023-1916", "CVE-2023-42829", "CVE-2023-42831",
                "CVE-2023-42832", "CVE-2023-1801", "CVE-2023-2426", "CVE-2023-2609",
                "CVE-2023-2610");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-12 12:02:00 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-07-25 15:52:56 +0530 (Tue, 25 Jul 2023)");
  script_name("Apple Mac OS X Security Update (HT213843)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper state and memory management.

  - Error in usage of curl.

  - Improper handling of sandbox processes.

  - Error in memory addressing.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, bypass security restrictions and disclose
  sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura versions prior to
  version 13.5");

  script_tag(name:"solution", value:"Upgrade to version 13.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213843");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^13\.");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13.5")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
