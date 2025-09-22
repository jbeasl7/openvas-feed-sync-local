# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14456.1");
  script_cve_id("CVE-2020-15652", "CVE-2020-15653", "CVE-2020-15654", "CVE-2020-15655", "CVE-2020-15656", "CVE-2020-15657", "CVE-2020-15658", "CVE-2020-15659", "CVE-2020-6463", "CVE-2020-6514");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:56 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 13:29:16 +0000 (Tue, 18 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14456-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14456-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014456-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174538");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-August/007275.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2020:14456-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

- Fix broken translation-loading (boo#1173991)
 * allow addon sideloading
 * mark signatures for langpacks non-mandatory
 * do not autodisable user profile scopes
- Google API key is not usable for geolocation service any more

- Mozilla Firefox 78.1 ESR
 * Fixed: Various stability, functionality, and security fixe
 (MFSA 2020-32) (bsc#1174538).
 * CVE-2020-15652 (bmo#1634872)
 Potential leak of redirect targets when loading scripts in a
 worker
 * CVE-2020-6514 (bmo#1642792)
 WebRTC data channel leaks internal address to peer
 * CVE-2020-15655 (bmo#1645204)
 Extension APIs could be used to bypass Same-Origin Policy
 * CVE-2020-15653 (bmo#1521542)
 Bypassing iframe sandbox when allowing popups
 * CVE-2020-6463 (bmo#1635293)
 Use-after-free in ANGLE gl::Texture::onUnbindAsSamplerTexture
 * CVE-2020-15656 (bmo#1647293)
 Type confusion for special arguments in IonMonkey
 * CVE-2020-15658 (bmo#1637745)
 Overriding file type when saving to disk
 * CVE-2020-15657 (bmo#1644954)
 DLL hijacking due to incorrect loading path
 * CVE-2020-15654 (bmo#1648333)
 Custom cursor can overlay user interface
 * CVE-2020-15659 (bmo#1550133, bmo#1633880, bmo#1643613,
 bmo#1644839, bmo#1645835, bmo#1646006, bmo#1646787,
 bmo#1649347, bmo#1650811, bmo#1651678)
 Memory safety bugs fixed in Firefox 79 and Firefox ESR 78.1

- Add sle11-icu-generation-python3.patch to fix icu-generation
 on big endian platforms

- Mozilla Firefox 78.0.2 ESR
 * MFSA 2020-28 (bsc#1173948)
 * MFSA-2020-0003 (bmo#1644076)
 X-Frame-Options bypass using object or embed tags
 * Fixed: Fixed an accessibility regression in reader mode
 (bmo#1650922)
 * Fixed: Made the address bar more resilient to data corruption
 in the user profile (bmo#1649981)
 * Fixed: Fixed a regression opening certain external
 applications (bmo#1650162)");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~78.1.0~78.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~78.1.0~78.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~78.1.0~78.87.1", rls:"SLES11.0SP4"))) {
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
