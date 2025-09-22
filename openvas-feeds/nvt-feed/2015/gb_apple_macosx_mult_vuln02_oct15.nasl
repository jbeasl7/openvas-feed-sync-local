# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806154");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-7761", "CVE-2015-7760", "CVE-2015-5922", "CVE-2015-5917",
                "CVE-2015-5915", "CVE-2015-5914", "CVE-2015-5913", "CVE-2015-5902",
                "CVE-2015-5901", "CVE-2015-5900", "CVE-2015-5897", "CVE-2015-5894",
                "CVE-2015-5893", "CVE-2015-5891", "CVE-2015-5890", "CVE-2015-5889",
                "CVE-2015-5888", "CVE-2015-5887", "CVE-2015-5884", "CVE-2015-5883",
                "CVE-2015-5878", "CVE-2015-5877", "CVE-2015-5875", "CVE-2015-5873",
                "CVE-2015-5872", "CVE-2015-5871", "CVE-2015-5870", "CVE-2015-5866",
                "CVE-2015-5865", "CVE-2015-5864", "CVE-2015-5854", "CVE-2015-5853",
                "CVE-2015-5849", "CVE-2015-5836", "CVE-2015-5833", "CVE-2015-5830",
                "CVE-2015-3785");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-10-29 13:24:34 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-02 (Oct 2015)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist. Please see the
  references for more details.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, bypass intended launch
  restrictions and access restrictions, cause a denial of service, write to
  arbitrary files, execute arbitrary code with system privilege.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.6.8 through
  10.11");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205267");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Sep/msg00008.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.([6-9|10)\.");

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
  if(version_in_range(version:osVer, test_version:"10.6.8", test_version2:"10.10.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.11");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
