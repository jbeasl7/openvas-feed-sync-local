# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807000");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2015-7044", "CVE-2015-7045", "CVE-2015-7052", "CVE-2015-7059",
                "CVE-2015-7060", "CVE-2015-7061", "CVE-2015-7062", "CVE-2015-7063",
                "CVE-2015-7067", "CVE-2015-7071", "CVE-2015-7076", "CVE-2015-7077",
                "CVE-2015-7078", "CVE-2015-7106", "CVE-2015-7108", "CVE-2015-7109",
                "CVE-2015-7110", "CVE-2015-7105", "CVE-2015-7074", "CVE-2015-7075",
                "CVE-2015-7053", "CVE-2011-2895", "CVE-2015-7115", "CVE-2015-7116",
                "CVE-2015-7064", "CVE-2015-7065", "CVE-2015-7066", "CVE-2015-7107",
                "CVE-2015-7058", "CVE-2015-7803", "CVE-2015-7804", "CVE-2015-7001",
                "CVE-2015-7094", "CVE-2015-7054", "CVE-2015-7081", "CVE-2015-7111",
                "CVE-2015-7112", "CVE-2015-7068", "CVE-2015-7040", "CVE-2015-7041",
                "CVE-2015-7042", "CVE-2015-7043", "CVE-2015-7083", "CVE-2015-7084",
                "CVE-2015-7047", "CVE-2015-7038", "CVE-2015-7039", "CVE-2012-0876",
                "CVE-2012-1147", "CVE-2012-1148", "CVE-2015-6908", "CVE-2015-5333",
                "CVE-2015-5334", "CVE-2015-7046", "CVE-2015-7073");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-30 15:22:00 +0000 (Thu, 30 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-12-15 12:46:20 +0530 (Tue, 15 Dec 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (Dec 2015)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - an error in Bluetooth HCI interface

  - an error in IOAcceleratorFamily

  - an error in Disk Images component

  - the System Integrity Protection feature mishandles union mounts

  - the Keychain Access improperly interacts with Keychain Agent

  - the Kext tools mishandles kernel-extension loading

  - an error in ASN.1 decode, kernel loader in EF, IOThunderboltFamily, in File
    Bookmark component

  - multiple errors in Intel Graphics Driver component

  - use-after-free error in Hypervisor

  - a privilege issue existed in handling union mounts

  - multiple vulnerabilities existed in LibreSSL

  - an input validation issue existed in OpenLDAP

  - an issue existed in how Keychain Access interacted with Keychain Agent

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, gain privileges,
  cause a denial of service, to spoof, to bypass protection mechanism.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.11 to 10.11.1,
  10.9.x through 10.9.5 and 10.10.x through 10.10.5.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.11.2 or later or apply security update 2015-005 for 10.10.x and security
  update 2015-008 for 10.9.x. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/HT205637");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78735");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78721");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78733");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Dec/msg00005.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(9|1[01])");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.(9|1[01])" || "Mac OS X" >!< osName){
  exit(0);
}

if((osVer == "10.9.5") || (osVer == "10.10.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1507"))
  {
    fix = "Apply Security Update 2015-008";
    osVer = osVer + " Build " + buildVer;
  }

  else if(osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1505"))
  {
    fix = "Apply Security Update 2015-005";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.9")
{
  if(version_is_less(version:osVer, test_version:"10.9.5")){
    fix = "Upgrade to latest OS release 10.9.5 and apply patch from vendor";
  }
}
else if(osVer =~ "^10\.10")
{
  if(version_is_less(version:osVer, test_version:"10.10.5")){
    fix = "Upgrade to latest OS release 10.10.5 and apply patch from vendor";
  }
}

else if(osVer =~ "^10\.11")
{
  if(version_is_less(version:osVer, test_version:"10.11.2")){
    fix = "10.11.2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
