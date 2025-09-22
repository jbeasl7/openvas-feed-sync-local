# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810929");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2010-0540", "CVE-2010-0302", "CVE-2010-1748", "CVE-2010-0545",
                "CVE-2010-0186", "CVE-2010-0187", "CVE-2010-0546", "CVE-2010-1374",
                "CVE-2010-1411", "CVE-2009-4212", "CVE-2010-0734", "CVE-2010-0541",
                "CVE-2010-1381", "CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580",
                "CVE-2009-1581", "CVE-2009-2964", "CVE-2010-1382");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:22:17 +0000 (Sat, 03 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-04-18 11:40:44 +0530 (Tue, 18 Apr 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (Apr 2017)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Wiki Server does not specify an explicit character set when serving
    HTML documents in response to user requests.

  - Multiple errors in SquirrelMail.

  - A configuration issue exists in Apple's distribution of Samba, the server
    used for SMB file sharing.

  - An input validation error in the Ruby WEBrick HTTP server's handling of
    error pages.

  - A buffer overflow exists in libcurl's handling of gzip-compressed web
    content.

  - An integer overflow exists in AES and RC4 decryption operations of the
    crypto library in the KDC server.

  - Multiple integer overflows in the handling of TIFF files.

  - A directory traversal issue exists in iChat's handling of inline
    image transfers.

  - A symlink following issue exists in Folder Manager.

  - Multiple errors in Adobe Flash Player plug-in.

  - An uninitialized memory read issue exists in the CUPS web interface's
    handling of form variables.

  - An use after free error exists in cupsd.

  - A cross-site request forgery issue exists in the CUPS web interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to conduct cross-site scripting attack, access sensitive information, cause
  an unexpected application termination or arbitrary code execution, upload
  files to arbitrary locations on the filesystem of a user and cause privilege
  escalation.");

  script_tag(name:"affected", value:"Apple Mac OS X and Mac OS X Server
  version 10.5.8, 10.6 through 10.6.3");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package_unreliable"); ## Build information is not available

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT4188");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40889");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38510");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40898");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38200");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40896");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40823");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37749");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34916");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40892");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[56]");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName)
{
  ## 10.5.8 prior to build X is also vulnerable.
  if(version_in_range(version:osVer, test_version:"10.6", test_version2:"10.6.3") ||
     version_in_range(version:osVer, test_version:"10.5", test_version2:"10.5.8"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.6.4 or apply patch");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
