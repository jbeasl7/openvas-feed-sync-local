# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814817");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-6219", "CVE-2019-6211", "CVE-2018-20346", "CVE-2018-20505",
                "CVE-2018-20506", "CVE-2019-6235");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-01-23 10:31:18 +0530 (Wed, 23 Jan 2019)");
  script_name("Apple Mac OS X Security Updates (HT209446)-02");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A denial of service issue which was addressed with improved validation.

  - A memory corruption issue which was addressed with improved state management.

  - Multiple memory corruption issues which were addressed with improved input
    validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service, execute arbitrary code and circumvent
  sandbox restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.14.x through 10.14.2");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.14.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209446");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.14");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer|| osVer !~ "^10\.14"|| "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.14",test_version2:"10.14.2"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.14.3");
  security_message(data:report);
  exit(0);
}

exit(99);
