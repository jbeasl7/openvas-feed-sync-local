# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836557");
  script_version("2025-09-03T05:38:18+0000");
  script_cve_id("CVE-2025-43191", "CVE-2025-43186", "CVE-2025-43244", "CVE-2025-31243",
                "CVE-2025-43253", "CVE-2025-43249", "CVE-2025-43248", "CVE-2025-43245",
                "CVE-2025-43222", "CVE-2025-43223", "CVE-2025-43220", "CVE-2025-43199",
                "CVE-2025-43210", "CVE-2025-43195", "CVE-2025-43187", "CVE-2025-43198",
                "CVE-2025-43254", "CVE-2025-43261", "CVE-2025-31279", "CVE-2025-24119",
                "CVE-2025-43255", "CVE-2025-43209", "CVE-2025-43226", "CVE-2025-43196",
                "CVE-2025-7424", "CVE-2025-43192", "CVE-2025-43275", "CVE-2025-43270",
                "CVE-2025-43225", "CVE-2025-43266", "CVE-2025-43260", "CVE-2025-43247",
                "CVE-2025-43194", "CVE-2025-43232", "CVE-2025-43236", "CVE-2025-43241",
                "CVE-2025-43233", "CVE-2025-43193", "CVE-2025-43250", "CVE-2025-43184",
                "CVE-2025-43197", "CVE-2025-43239", "CVE-2025-43243", "CVE-2025-43246",
                "CVE-2025-43256", "CVE-2025-43206", "CVE-2025-43189", "CVE-2025-43259",
                "CVE-2025-43238", "CVE-2025-43284");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-27 18:00:52 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-07-30 17:24:15 +0530 (Wed, 30 Jul 2025)");
  script_name("Apple MacOSX Security Update (HT124150)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, elevate privileges, bypass
  security restrictions and cause denial of service.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version
  14.7.7");

  script_tag(name:"solution", value:"Update macOS Sonoma to version 14.7.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/124150");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_less(version:osVer, test_version:"14.7.7")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.7.7");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
