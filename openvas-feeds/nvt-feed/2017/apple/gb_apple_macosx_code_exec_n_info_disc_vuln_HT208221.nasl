# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811962");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2017-13786", "CVE-2017-13800", "CVE-2018-4390", "CVE-2018-4391",
                "CVE-2017-13907", "CVE-2017-13852");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-27 16:28:00 +0000 (Mon, 27 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-11-02 12:06:10 +0530 (Thu, 02 Nov 2017)");
  script_name("Apple Mac OS X Code Execution And Information Disclosure Vulnerabilities (HT208221)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to code execution and information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An issue existed in the handling of DMA.

  - A memory corruption issue.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code with system privileges and also can recover unencrypted
  APFS file system data.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.13");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.13.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208221");
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
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName && osVer == "10.13")
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.13.1");
  security_message(data:report);
  exit(0);
}

exit(99);
