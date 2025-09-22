# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810220");
  script_version("2024-02-19T14:37:31+0000");
  script_cve_id("CVE-2014-1314", "CVE-2014-1315", "CVE-2014-1316", "CVE-2014-1318",
                "CVE-2014-1319", "CVE-2014-1321", "CVE-2014-1322", "CVE-2014-1296",
                "CVE-2014-1320", "CVE-2013-6393", "CVE-2013-4164", "CVE-2014-1295");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-11-17 22:43:28 -0800 (Thu, 17 Nov 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-02 (Nov 2016)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The windowServer does not prevent session creation by a sandboxed
    application.

  - A format string error in CoreServicesUIAgent.

  - The Intel Graphics Driver does not properly validate a certain pointer.

  - A buffer overflow error in ImageIO.

  - An improper implementation of power management.

  - The kernel places a kernel pointer into an XNU object data structure
    accessible from user space.

  - An error in Heimdal Kerberos.

  - An error in CFNetwork HTTPProtocol.

  - An error in IOKit Kernel.

  - An integer overflow issue existed in LibYAML's handling of YAML tags.

  - A heap-based buffer overflow issue error in Ruby.

  - An error in secure transport regarding renegotiation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption), to
  gain sensitive information and to bypass certain protection mechanism and
  have other impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.9.x through
  10.9.2");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT202966");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63873");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67023");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67024");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65258");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63873");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67025");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.9.");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName && osVer =~ "^10\.9")
{
  if(version_in_range(version:osVer, test_version:"10.9.0", test_version2:"10.9.1")){
    fix = "Upgrade to latest OS release 10.9.2 and apply patch from vendor" ;
  }

  else if(osVer == "10.9.2")
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    if(!buildVer){
      exit(0);
    }

    if(version_is_less(version:buildVer, test_version:"13C1021"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);