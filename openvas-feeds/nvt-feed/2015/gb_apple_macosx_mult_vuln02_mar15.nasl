# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805484");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-8839", "CVE-2014-8836");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-03-05 17:54:00 +0530 (Thu, 05 Mar 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities -02 (Mar 2015)");
  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The flaw in Spotlight that is triggered as the status of Mails
    'load remote content in messages' setting is not properly checked

  - The flaw in the Bluetooth driver that is triggered can allow a specially
    crafted application to control the size of a write to kernel memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to determine the IP address of the recipient of an email, a local
  attacker to gain elevated privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.10.x through
  10.10.1");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version 10.10.2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT204244");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72328");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.10\.");

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
  if(version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.1"))
  {
    fix = "10.10.2";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version:     ' + fix + '\n';
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);