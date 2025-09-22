# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810209");
  script_version("2024-02-19T14:37:31+0000");
  script_cve_id("CVE-2016-1792", "CVE-2016-1791", "CVE-2016-1793", "CVE-2016-1794",
                "CVE-2016-1795", "CVE-2016-1796", "CVE-2016-1797", "CVE-2016-1798",
                "CVE-2016-1799", "CVE-2016-1800", "CVE-2016-1801", "CVE-2016-1802",
                "CVE-2016-1803", "CVE-2016-1805", "CVE-2016-1806", "CVE-2016-1807",
                "CVE-2016-1808", "CVE-2016-1809", "CVE-2016-1810", "CVE-2016-1811",
                "CVE-2016-1812", "CVE-2016-1860", "CVE-2016-1862", "CVE-2016-1814",
                "CVE-2016-1815", "CVE-2016-1817", "CVE-2016-1818", "CVE-2016-1819",
                "CVE-2016-1853", "CVE-2016-1851", "CVE-2016-1850", "CVE-2016-1848",
                "CVE-2016-1847", "CVE-2016-1861", "CVE-2016-1846", "CVE-2016-1804",
                "CVE-2016-1843", "CVE-2016-1844", "CVE-2016-1842", "CVE-2016-1841",
                "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836",
                "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840",
                "CVE-2016-1832", "CVE-2016-1826", "CVE-2016-1827", "CVE-2016-1828",
                "CVE-2016-1829", "CVE-2016-1830", "CVE-2016-1831", "CVE-2016-1825",
                "CVE-2016-1823", "CVE-2016-1824", "CVE-2016-1822", "CVE-2016-1821",
                "CVE-2016-1820", "CVE-2016-1816", "CVE-2016-1813", "CVE-2015-8865",
                "CVE-2016-3141", "CVE-2016-3142", "CVE-2016-4070", "CVE-2016-4071",
                "CVE-2016-4072", "CVE-2016-4073", "CVE-2016-4650");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 17:10:00 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-11-22 11:05:47 +0530 (Tue, 22 Nov 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (Nov 2016)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, bypass certain protection
  mechanism and have other impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.11.x before
  10.11.5");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.11.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206567");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90696");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90694");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.11");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName && osVer =~ "^10\.11")
{
  if(version_is_less(version:osVer, test_version:"10.11.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.11.5");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
