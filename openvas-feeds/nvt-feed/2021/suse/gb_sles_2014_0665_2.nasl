# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0665.2");
  script_cve_id("CVE-2014-1492", "CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-04-30 17:51:26 +0000 (Wed, 30 Apr 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0665-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0665-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140665-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2014:0665-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This Mozilla Firefox update provides several security and non-security fixes.

Mozilla Firefox has been updated to the 24.5.0esr version, which fixes the following issues:

 * MFSA 2014-34/CVE-2014-1518 Miscellaneous memory safety hazards
 * MFSA 2014-37/CVE-2014-1523 Out of bounds read while decoding JPG
 images
 * MFSA 2014-38/CVE-2014-1524 Buffer overflow when using non-XBL object
 as XBL
 * MFSA 2014-42/CVE-2014-1529 Privilege escalation through Web
 Notification API
 * MFSA 2014-43/CVE-2014-1530 Cross-site scripting (XSS) using history
 navigations
 * MFSA 2014-44/CVE-2014-1531 Use-after-free in imgLoader while
 resizing images
 * MFSA 2014-46/CVE-2014-1532 Use-after-free in nsHostResolver

Mozilla NSS has been updated to version 3.16

 * required for Firefox 29
 * CVE-2014-1492_ In a wildcard certificate, the wildcard character
 should not be embedded within the U-label of an internationalized
 domain name. See the last bullet point in RFC 6125, Section 7.2.
 * Update of root certificates.

Security Issue references:

 * CVE-2014-1532
 * CVE-2014-1531
 * CVE-2014-1530
 * CVE-2014-1529
 * CVE-2014-1524
 * CVE-2014-1523
 * CVE-2014-1518
 * CVE-2014-1492");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Server 10-SP3.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.5.0esr~0.7.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~24~0.12.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~24.5.0esr~0.7.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-atk", rpm:"firefox-atk~1.28.0~0.7.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-atk-32bit", rpm:"firefox-atk-32bit~1.28.0~0.7.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cairo", rpm:"firefox-cairo~1.8.0~0.10.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cairo-32bit", rpm:"firefox-cairo-32bit~1.8.0~0.10.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fontconfig", rpm:"firefox-fontconfig~2.6.0~0.7.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fontconfig-32bit", rpm:"firefox-fontconfig-32bit~2.6.0~0.7.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-freetype2", rpm:"firefox-freetype2~2.3.7~0.35.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-freetype2-32bit", rpm:"firefox-freetype2-32bit~2.3.7~0.35.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-glib2", rpm:"firefox-glib2~2.22.5~0.13.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-glib2-32bit", rpm:"firefox-glib2-32bit~2.22.5~0.13.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk2", rpm:"firefox-gtk2~2.18.9~0.9.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk2-32bit", rpm:"firefox-gtk2-32bit~2.18.9~0.9.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk2-lang", rpm:"firefox-gtk2-lang~2.18.9~0.9.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgcc_s1-32bit", rpm:"firefox-libgcc_s1-32bit~4.7.2_20130108~0.22.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgcc_s1", rpm:"firefox-libgcc_s1~4.7.2_20130108~0.22.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6-32bit", rpm:"firefox-libstdc++6-32bit~4.7.2_20130108~0.22.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6", rpm:"firefox-libstdc++6~4.7.2_20130108~0.22.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pango", rpm:"firefox-pango~1.26.2~0.9.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pango-32bit", rpm:"firefox-pango-32bit~1.26.2~0.9.2", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pcre-32bit", rpm:"firefox-pcre-32bit~7.8~0.8.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pcre", rpm:"firefox-pcre~7.8~0.8.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pixman", rpm:"firefox-pixman~0.16.0~0.7.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pixman-32bit", rpm:"firefox-pixman-32bit~0.16.0~0.7.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.10.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.16~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.16~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.16~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.16~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191", rpm:"mozilla-xulrunner191~1.9.1.19~0.13.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-32bit", rpm:"mozilla-xulrunner191-32bit~1.9.1.19~0.13.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs", rpm:"mozilla-xulrunner191-gnomevfs~1.9.1.19~0.13.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs-32bit", rpm:"mozilla-xulrunner191-gnomevfs-32bit~1.9.1.19~0.13.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-translations", rpm:"mozilla-xulrunner191-translations~1.9.1.19~0.13.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-translations-32bit", rpm:"mozilla-xulrunner191-translations-32bit~1.9.1.19~0.13.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192", rpm:"mozilla-xulrunner192~1.9.2.28~0.13.4", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-32bit", rpm:"mozilla-xulrunner192-32bit~1.9.2.28~0.13.4", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome", rpm:"mozilla-xulrunner192-gnome~1.9.2.28~0.13.4", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome-32bit", rpm:"mozilla-xulrunner192-gnome-32bit~1.9.2.28~0.13.4", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations", rpm:"mozilla-xulrunner192-translations~1.9.2.28~0.13.4", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-32bit", rpm:"mozilla-xulrunner192-translations-32bit~1.9.2.28~0.13.4", rls:"SLES10.0SP3"))) {
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
