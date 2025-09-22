# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0688.1");
  script_cve_id("CVE-2011-1187", "CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0688-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120688-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2012:0688-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox was updated to the 10.0.4 ESR release to fix various bugs and security issues.

 *

 Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances,
and we presume that with enough effort at least some of these could be exploited to run arbitrary code. (MFSA 2012-20)

 In general these flaws cannot be exploited through email in the Thunderbird and SeaMonkey products because scripting is disabled, but are potentially a risk in browser or browser-like contexts in those products.

 o

 Christian Holler a reported memory safety and security problem affecting Firefox 11. (CVE-2012-0468)

 o

 Bob Clary, Christian Holler, Brian Hackett,
Bobby Holley, Gary Kwong, Hilary Hall, Honza Bambas, Jesse Ruderman, Julian Seward, and Olli Pettay reported memory safety problems and crashes that affect Firefox ESR and Firefox 11. (CVE-2012-0467)

 *

 Using the Address Sanitizer tool, security researcher Aki Helin from OUSPG found that IDBKeyRange of indexedDB remains in the XPConnect hashtable instead of being unlinked before being destroyed. When it is destroyed, this causes a use-after-free, which is potentially exploitable.
(MFSA 2012-22 / CVE-2012-0469)

 *

 Using the Address Sanitizer tool, security researcher Atte Kettunen from OUSPG found a heap corruption in gfxImageSurface which allows for invalid frees and possible remote code execution. This happens due to float error,
resulting from graphics values being passed through different number systems. (MFSA 2012-23 / CVE-2012-0470)

 *

 Anne van Kesteren of Opera Software found a multi-octet encoding issue where certain octets will destroy the following octets in the processing of some multibyte character sets. This can leave users vulnerable to cross-site scripting (XSS) attacks on maliciously crafted web pages. (MFSA 2012-24 / CVE-2012-0471)

 *

 Security research firm iDefense reported that researcher wushi of team509 discovered a memory corruption on Windows Vista and Windows 7 systems with hardware acceleration disabled or using incompatible video drivers.
This is created by using cairo-dwrite to attempt to render fonts on an unsupported code path. This corruption causes a potentially exploitable crash on affected systems. (MFSA 2012-25 / CVE-2012-0472)

 *

 Mozilla community member Matias Juntunen discovered an error in WebGLBuffer where FindMaxElementInSubArray receives wrong template arguments from FindMaxUshortElement. This bug causes maximum index to be computed incorrectly within WebGL.drawElements, allowing the reading of illegal video memory. (MFSA 2012-26 /
CVE-2012-0473)

 *

 Security researchers Jordi Chancel and Eddy Bordi reported that they could short-circuit page loads to show the address of a different site than what is loaded in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~10.0.4~0.7.6", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.8.12", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~10.0.4~0.7.6", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox3-gtk2", rpm:"firefox3-gtk2~2.10.6~0.10.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox3-gtk2-32bit", rpm:"firefox3-gtk2-32bit~2.10.6~0.10.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.13.4~0.5.5", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.13.4~0.5.5", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-64bit", rpm:"mozilla-nss-64bit~3.13.4~0.5.5", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.13.4~0.5.5", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.13.4~0.5.5", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.13.4~0.5.5", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
