# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834713");
  script_version("2025-01-22T05:38:11+0000");
  script_cve_id("CVE-2024-44255", "CVE-2024-44270", "CVE-2024-44280", "CVE-2024-44126",
                "CVE-2024-44260", "CVE-2024-44295", "CVE-2024-44240", "CVE-2024-44302",
                "CVE-2024-44213", "CVE-2024-40855", "CVE-2024-44289", "CVE-2024-44282",
                "CVE-2024-44265", "CVE-2024-44215", "CVE-2024-44297", "CVE-2024-44216",
                "CVE-2024-44287", "CVE-2024-44197", "CVE-2024-44239", "CVE-2024-44122",
                "CVE-2024-44222", "CVE-2024-44256", "CVE-2024-44156", "CVE-2024-44159",
                "CVE-2024-44196", "CVE-2024-44253", "CVE-2024-44247", "CVE-2024-44267",
                "CVE-2024-44301", "CVE-2024-44275", "CVE-2024-44294", "CVE-2024-44137",
                "CVE-2024-44254", "CVE-2024-44269", "CVE-2024-44236", "CVE-2024-44237",
                "CVE-2024-44284", "CVE-2024-44279", "CVE-2024-44281", "CVE-2024-44283",
                "CVE-2024-44278", "CVE-2024-44264", "CVE-2024-44257", "CVE-2024-44232",
                "CVE-2024-44233", "CVE-2024-44234", "CVE-2024-54471", "CVE-2024-54538",
                "CVE-2024-40854");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-29 17:38:18 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-30 10:36:04 +0530 (Wed, 30 Oct 2024)");
  script_name("Apple MacOSX Security Update (HT121568)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-44278: An information disclosure issue was addressed with improved private data redaction for log entries

  - CVE-2024-44294: A path deletion vulnerability was addressed by preventing vulnerable code from running with privileges");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, elevate privileges, conduct
  spoofing and cause denial of service.");

  script_tag(name:"affected", value:"Apple macOS Ventura prior to version
  13.7.1.");

  script_tag(name:"solution", value:"Update macOS Ventura to version 13.7.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/121568");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:osVer, test_version:"13.7.1")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.7.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
