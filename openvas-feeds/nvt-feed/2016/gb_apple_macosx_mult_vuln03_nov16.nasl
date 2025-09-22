# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810222");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2014-1314", "CVE-2013-5170", "CVE-2014-1296", "CVE-2014-1318",
                "CVE-2013-4164", "CVE-2014-1295");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-11-17 22:43:28 -0800 (Thu, 17 Nov 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-03 (Nov 2016)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The windowServer does not prevent session creation by a sandboxed
    application.

  - A buffer underflow error in CoreGraphics.

  - The CFNetwork does not ensure that a Set-Cookie HTTP header is complete
    before interpreting the header's value.

  - The Intel Graphics Driver does not properly validate a certain pointer.

  - A heap-based buffer overflow error in Ruby.

  - The Secure Transport does not ensure that a server's X.509 certificate is
    the same during renegotiation as it was before renegotiation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption), to
  gain sensitive information and to bypass certain protection mechanism and
  have other impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.8.x through
  10.8.5");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package_unreliable"); ## Build information is not available

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT202966");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63330");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63873");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67024");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.8\.");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName && osVer =~ "^10\.8")
{
  if(version_in_range(version:osVer, test_version:"10.8.0", test_version2:"10.8.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"See vendor advisory");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
