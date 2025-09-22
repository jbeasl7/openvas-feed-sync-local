# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826502");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-7463", "CVE-2020-8037", "CVE-2020-8284", "CVE-2020-8285",
                "CVE-2020-8286", "CVE-2021-1739", "CVE-2021-1740", "CVE-2021-1770",
                "CVE-2021-1784", "CVE-2021-1808", "CVE-2021-1809", "CVE-2021-1810",
                "CVE-2021-1811", "CVE-2021-1813", "CVE-2021-1814", "CVE-2021-1815",
                "CVE-2021-1817", "CVE-2021-1820", "CVE-2021-1824", "CVE-2021-1825",
                "CVE-2021-1826", "CVE-2021-1828", "CVE-2021-1829", "CVE-2021-1832",
                "CVE-2021-1834", "CVE-2021-1839", "CVE-2021-1840", "CVE-2021-1841",
                "CVE-2021-1843", "CVE-2021-1846", "CVE-2021-1847", "CVE-2021-1849",
                "CVE-2021-1851", "CVE-2021-1853", "CVE-2021-1855", "CVE-2021-1857",
                "CVE-2021-1858", "CVE-2021-1859", "CVE-2021-1860", "CVE-2021-1861",
                "CVE-2021-1867", "CVE-2021-1868", "CVE-2021-1872", "CVE-2021-1873",
                "CVE-2021-1875", "CVE-2021-1876", "CVE-2021-1878", "CVE-2021-1880",
                "CVE-2021-1881", "CVE-2021-1882", "CVE-2021-1883", "CVE-2021-1884",
                "CVE-2021-1885", "CVE-2021-30652", "CVE-2021-30653", "CVE-2021-30655",
                "CVE-2021-30657", "CVE-2021-30658", "CVE-2021-30659", "CVE-2021-30660",
                "CVE-2021-30661", "CVE-2021-30664", "CVE-2021-30743", "CVE-2021-30750",
                "CVE-2021-30752", "CVE-2021-30856");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-15 12:31:00 +0000 (Wed, 15 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-09-02 11:24:06 +0530 (Fri, 02 Sep 2022)");
  script_name("Apple Mac OS X Security Update (HT212325)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information
  on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions, execute arbitrary code, cause denial of service
  and disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.3.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212325");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"11.3"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.3");
  security_message(data:report);
  exit(0);
}
exit(99);
