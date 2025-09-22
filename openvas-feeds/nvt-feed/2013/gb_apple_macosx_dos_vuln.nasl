# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804183");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-6799");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-31 20:51:30 +0530 (Tue, 31 Dec 2013)");
  script_name("Apple Mac OS X Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of user-input when handling hard
  links.");

  script_tag(name:"affected", value:"Mac OS X version 10.9.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker to corrupt memory and
  cause a denial of service.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/447755.php");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013110059");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.9");

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
  if(version_is_equal(version:osVer, test_version:"10.9"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
  exit(99);
}

exit(0);
