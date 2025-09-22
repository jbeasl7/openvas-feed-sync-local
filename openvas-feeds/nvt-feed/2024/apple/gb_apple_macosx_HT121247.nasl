# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834620");
  script_version("2025-03-18T05:38:50+0000");
  script_cve_id("CVE-2024-44153", "CVE-2024-44182", "CVE-2024-40846", "CVE-2024-40845",
                "CVE-2024-44154", "CVE-2024-40847", "CVE-2024-44164", "CVE-2024-44168",
                "CVE-2024-40848", "CVE-2024-40841", "CVE-2024-44135", "CVE-2024-44128",
                "CVE-2024-44151", "CVE-2024-27876", "CVE-2024-44177", "CVE-2024-40850",
                "CVE-2024-27880", "CVE-2024-44176", "CVE-2024-44160", "CVE-2024-44161",
                "CVE-2024-44169", "CVE-2024-44165", "CVE-2024-40791", "CVE-2024-44181",
                "CVE-2024-44183", "CVE-2024-44167", "CVE-2024-44178", "CVE-2024-40797",
                "CVE-2024-44163", "CVE-2024-44125", "CVE-2024-40801", "CVE-2024-44158",
                "CVE-2024-40844", "CVE-2024-40860", "CVE-2024-44166", "CVE-2024-44190",
                "CVE-2024-44184", "CVE-2024-54469");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-24 15:57:03 +0000 (Tue, 24 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-20 16:08:55 +0530 (Fri, 20 Sep 2024)");
  script_name("Apple MacOSX Security Update (HT121247)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-44154: A memory initialization issue was addressed with improved memory handling

  - CVE-2024-44168: A library injection issue was addressed with additional restrictions");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, bypass security restrictions,
  conduct spoofing and cause denial of service.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version
  14.7");

  script_tag(name:"solution", value:"Update macOS Sonoma to version 14.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/121247");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^14\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"14.7")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.7");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
