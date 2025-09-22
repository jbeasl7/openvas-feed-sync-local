# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806148");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2015-5943", "CVE-2015-6983", "CVE-2015-7061", "CVE-2015-7060",
                "CVE-2015-7059", "CVE-2015-7007", "CVE-2015-5945", "CVE-2015-6563",
                "CVE-2014-3565", "CVE-2012-6151", "CVE-2015-7988", "CVE-2015-6994",
                "CVE-2015-6988", "CVE-2015-6974", "CVE-2015-7021", "CVE-2015-7020",
                "CVE-2015-7019", "CVE-2015-7008", "CVE-2015-6990", "CVE-2015-6987",
                "CVE-2015-6995", "CVE-2015-7017", "CVE-2015-7015", "CVE-2015-7023",
                "CVE-2015-7006", "CVE-2015-7003");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-19 16:46:00 +0000 (Wed, 19 Jun 2019)");
  script_tag(name:"creation_date", value:"2015-10-29 12:54:16 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (Oct 2015)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist. Please see the
  references for more details.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code, overwrite cookies, elevate privileges, execute
  arbitrary code with system privileges, cause unexpected application termination,
  read kernel memory, conduct impersonation attacks, run arbitrary AppleScript,
  overwrite arbitrary files and control keychain access prompts.");

  script_tag(name:"affected", value:"Apple OS X El Capitan versions before
  10.11.1");

  script_tag(name:"solution", value:"Upgrade Apple OS X El Capitan to version
  10.11.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205375");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.11");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(osVer && osVer =~ "^10\.11")
{

  if(version_is_less(version:osVer, test_version:"10.11.1"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.11.1");
    security_message(data:report);
    exit(0);
  }
}

exit(99);
