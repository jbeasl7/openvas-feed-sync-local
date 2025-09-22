# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812408");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-13876", "CVE-2017-13875", "CVE-2017-13871", "CVE-2017-13860",
                "CVE-2017-13883", "CVE-2017-13848", "CVE-2017-13858", "CVE-2017-13878",
                "CVE-2017-13865");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-12-07 10:51:33 +0530 (Thu, 07 Dec 2017)");
  script_name("Apple Mac OS X Security Updates (HT208331)-04");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Security update resolves,

  - A memory corruption issue was addressed with improved memory handling.

  - An out-of-bounds read was addressed through improved bounds checking.

  - A logic error existed in the validation of credentials.

  - An inconsistent user interface issue was addressed with improved state management.

  - An input validation issue existed in the kernel.

  - An out-of-bounds read issue existed that led to the disclosure of kernel memory.

  - A validation issue was addressed with improved input sanitization.

  - An encryption issue existed with S/MIME credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code with kernel and system privileges. Also
  attacker may be able to bypass administrator authentication without supplying
  the administrator's password.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.13.1");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.13.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208331");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.13");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.13" || "Mac OS X" >!< osName){
  exit(0);
}

if(osVer == "10.13.1")
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.13.2");
  security_message(data:report);
  exit(0);
}

exit(99);
