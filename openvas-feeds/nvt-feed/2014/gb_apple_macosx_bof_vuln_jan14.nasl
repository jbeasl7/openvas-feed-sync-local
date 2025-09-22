# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804062");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-0984", "CVE-2013-0155", "CVE-2013-0276", "CVE-2013-0277",
                "CVE-2013-0333", "CVE-2013-1854", "CVE-2013-1855", "CVE-2013-1856",
                "CVE-2013-1857");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-20 20:19:58 +0530 (Mon, 20 Jan 2014)");
  script_name("Apple Mac OS X Directory Service Remote Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper
  handling of network messages and multiple errors in ruby on rails.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to, execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.6.8");

  script_tag(name:"solution", value:"Apply the Mac Security Update 2013-002. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60328");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.8");

  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if(osVer == "10.6.8")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(version_is_less(version:buildVer, test_version:"10K1115"))
  {
    osVer = osVer + " Build " + buildVer;
    report = report_fixed_ver(installed_version:osVer, fixed_version:"Apply security update 2013-002 from vendor");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);