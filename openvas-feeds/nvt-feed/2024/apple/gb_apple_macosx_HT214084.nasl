# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832879");
  script_version("2025-02-12T05:37:43+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-23291", "CVE-2024-23276", "CVE-2024-23227", "CVE-2024-23233",
                "CVE-2024-23269", "CVE-2024-23288", "CVE-2024-23277", "CVE-2024-23247",
                "CVE-2024-23248", "CVE-2024-23249", "CVE-2024-23250", "CVE-2024-23244",
                "CVE-2024-23205", "CVE-2022-48554", "CVE-2024-23253", "CVE-2024-23270",
                "CVE-2024-23257", "CVE-2024-23258", "CVE-2024-23286", "CVE-2024-23234",
                "CVE-2024-23266", "CVE-2024-23235", "CVE-2024-23265", "CVE-2024-23225",
                "CVE-2024-23278", "CVE-2024-0258", "CVE-2024-23279", "CVE-2024-23287",
                "CVE-2024-23264", "CVE-2024-23285", "CVE-2024-23283", "CVE-2023-48795",
                "CVE-2023-51384", "CVE-2023-51385", "CVE-2022-42816", "CVE-2024-23216",
                "CVE-2024-23267", "CVE-2024-23268", "CVE-2024-23274", "CVE-2023-42853",
                "CVE-2024-23275", "CVE-2024-23255", "CVE-2024-23294", "CVE-2024-23296",
                "CVE-2024-23259", "CVE-2024-23273", "CVE-2024-23238", "CVE-2024-23239",
                "CVE-2024-23290", "CVE-2024-23232", "CVE-2024-23231", "CVE-2024-23230",
                "CVE-2024-23245", "CVE-2024-23292", "CVE-2024-23289", "CVE-2024-23293",
                "CVE-2024-23241", "CVE-2024-23272", "CVE-2024-23242", "CVE-2024-23281",
                "CVE-2024-23260", "CVE-2024-23246", "CVE-2024-23226", "CVE-2024-23254",
                "CVE-2024-23263", "CVE-2024-23280", "CVE-2024-23284", "CVE-2024-27853",
                "CVE-2024-27809", "CVE-2024-27887", "CVE-2024-27888", "CVE-2024-23261",
                "CVE-2024-27886", "CVE-2024-27859", "CVE-2024-54658");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-12 05:37:43 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-05 16:33:06 +0000 (Thu, 05 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-03-22 16:19:56 +0530 (Fri, 22 Mar 2024)");
  script_name("Apple Mac OS X Security Update (HT214084)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-23273: Private Browsing tabs may be accessed without authentication

  - CVE-2024-23263: Processing maliciously crafted web content may prevent Content Security Policy from being enforced

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct arbitrary code execution, information disclosure and denial of
  service.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version
  14.4");

  script_tag(name:"solution", value:"Update macOS Sonoma to version 14.4 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214084");
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

if(version_is_less(version:osVer, test_version:"14.4")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.4");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
