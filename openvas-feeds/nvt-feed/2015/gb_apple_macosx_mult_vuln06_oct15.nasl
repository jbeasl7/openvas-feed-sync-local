# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806151");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2014-4459", "CVE-2014-4458");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2015-10-29 14:23:09 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-06 (Oct 2015)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist in WebKit and
  the 'System Profiler About This Mac' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code via crafted page objects in an HTML document.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.x before
  10.10.1");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.10.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2014/Nov/msg00001.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.([0-9]|10)\.");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(osVer =~ "^10\.([0-9]|10)\." && version_is_less(version:osVer, test_version:"10.10.1"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.10.1");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
