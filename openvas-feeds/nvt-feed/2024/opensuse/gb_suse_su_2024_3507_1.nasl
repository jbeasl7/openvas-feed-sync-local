# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856527");
  script_cve_id("CVE-2024-6600", "CVE-2024-6601", "CVE-2024-6602", "CVE-2024-6603", "CVE-2024-6604", "CVE-2024-6606", "CVE-2024-6607", "CVE-2024-6608", "CVE-2024-6609", "CVE-2024-6610", "CVE-2024-6611", "CVE-2024-6612", "CVE-2024-6613", "CVE-2024-6614", "CVE-2024-6615", "CVE-2024-7518", "CVE-2024-7519", "CVE-2024-7520", "CVE-2024-7521", "CVE-2024-7522", "CVE-2024-7525", "CVE-2024-7526", "CVE-2024-7527", "CVE-2024-7528", "CVE-2024-7529", "CVE-2024-8381", "CVE-2024-8382", "CVE-2024-8384", "CVE-2024-8385", "CVE-2024-8386", "CVE-2024-8387", "CVE-2024-8394");
  script_tag(name:"creation_date", value:"2024-10-04 04:00:31 +0000 (Fri, 04 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 15:44:52 +0000 (Wed, 04 Sep 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3507-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3507-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243507-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229821");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-October/019538.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2024:3507-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

- Mozilla Thunderbird 128.2.3
 MFSA 2024-43 (bsc#1229821)
 * CVE-2024-8394: Crash when aborting verification of OTR chat.
 * CVE-2024-8385: WASM type confusion involving ArrayTypes.
 * CVE-2024-8381: Type confusion when looking up a property name in a 'with' block.
 * CVE-2024-8382: Internal event interfaces were exposed to web content when browser EventHandler listener callbacks
 ran.
 * CVE-2024-8384: Garbage collection could mis-color cross-compartment objects in OOM conditions.
 * CVE-2024-8386: SelectElements could be shown over another site if popups are allowed.
 * CVE-2024-8387: Memory safety bugs fixed in Firefox 130, Firefox ESR 128.2, and Thunderbird 128.2.
 MFSA 2024-37 (bsc#1228648)
 * CVE-2024-7518: Fullscreen notification dialog can be obscured by document content.
 * CVE-2024-7519: Out of bounds memory access in graphics shared memory handling.
 * CVE-2024-7520: Type confusion in WebAssembly.
 * CVE-2024-7521: Incomplete WebAssembly exception handing.
 * CVE-2024-7522: Out of bounds read in editor component.
 * CVE-2024-7525: Missing permission check when creating a StreamFilter.
 * CVE-2024-7526: Uninitialized memory used by WebGL.
 * CVE-2024-7527: Use-after-free in JavaScript garbage collection.
 * CVE-2024-7528: Use-after-free in IndexedDB.
 * CVE-2024-7529: Document content could partially obscure security prompts.
 MFSA 2024-32 (bsc#1226316)
 * CVE-2024-6606: Out-of-bounds read in clipboard component.
 * CVE-2024-6607: Leaving pointerlock by pressing the escape key could be prevented.
 * CVE-2024-6608: Cursor could be moved out of the viewport using pointerlock.
 * CVE-2024-6609: Memory corruption in NSS.
 * CVE-2024-6610: Form validation popups could block exiting full-screen mode.
 * CVE-2024-6600: Memory corruption in WebGL API.
 * CVE-2024-6601: Race condition in permission assignment.
 * CVE-2024-6602: Memory corruption in NSS.
 * CVE-2024-6603: Memory corruption in thread creation.
 * CVE-2024-6611: Incorrect handling of SameSite cookies.
 * CVE-2024-6612: CSP violation leakage when using devtools.
 * CVE-2024-6613: Incorrect listing of stack frames.
 * CVE-2024-6614: Incorrect listing of stack frames.
 * CVE-2024-6604: Memory safety bugs fixed in Firefox 128, Firefox ESR 115.13, Thunderbird 128, and Thunderbird
 115.13.
 * CVE-2024-6615: Memory safety bugs fixed in Firefox 128 and Thunderbird 128.

Bug fixes:
- Recommend libfido2-udev in order to try to get security keys (e.g. Yubikeys) working out of the box. (bsc#1184272)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.2.3~150200.8.177.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.2.3~150200.8.177.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.2.3~150200.8.177.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.2.3~150200.8.177.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.2.3~150200.8.177.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.2.3~150200.8.177.1", rls:"openSUSELeap15.6"))) {
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
