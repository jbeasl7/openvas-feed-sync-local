# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2081.1");
  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4497", "CVE-2015-4498", "CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4513", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-11-05 15:41:35 +0000 (Thu, 05 Nov 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2081-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2081-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152081-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2015:2081-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox ESR was updated to version 38.4.0ESR to fix multiple security issues.
MFSA 2015-116/CVE-2015-4513 Miscellaneous memory safety hazards (rv:42.0 / rv:38.4)
MFSA 2015-122/CVE-2015-7188 Trailing whitespace in IP address hostnames can bypass same-origin policy MFSA 2015-123/CVE-2015-7189 Buffer overflow during image interactions in canvas MFSA 2015-127/CVE-2015-7193 CORS preflight is bypassed when non-standard Content-Type headers are received MFSA 2015-128/CVE-2015-7194 Memory corruption in libjar through zip files MFSA 2015-130/CVE-2015-7196 JavaScript garbage collection crash with Java applet MFSA 2015-131/CVE-2015-7198/CVE-2015-7199/CVE-2015-7200 Vulnerabilities found through code inspection MFSA 2015-132/CVE-2015-7197 Mixed content WebSocket policy bypass through workers MFSA 2015-133/CVE-2015-7181/CVE-2015-7182/CVE-2015-7183 NSS and NSPR memory corruption issues It also includes fixes from 38.3.0ESR:
MFSA 2015-96/CVE-2015-4500/CVE-2015-4501 Miscellaneous memory safety hazards (rv:41.0 / rv:38.3)
MFSA 2015-101/CVE-2015-4506 Buffer overflow in libvpx while parsing vp9 format video MFSA 2015-105/CVE-2015-4511 Buffer overflow while decoding WebM video MFSA 2015-106/CVE-2015-4509 Use-after-free while manipulating HTML media content MFSA 2015-110/CVE-2015-4519 Dragging and dropping images exposes final URL after redirects MFSA 2015-111/CVE-2015-4520 Errors in the handling of CORS preflight request headers MFSA 2015-112/CVE-2015-4517/CVE-2015-4521/CVE-2015-4522 CVE-2015-7174/CVE-2015-7175/CVE-2015-7176/CVE-2015-7177 CVE-2015-7180
Vulnerabilities found through code inspection It also includes fixes from the Firefox 38.2.1ESR release:
MFSA 2015-94/CVE-2015-4497 (bsc#943557)
Use-after-free when resizing canvas element during restyling MFSA 2015-95/CVE-2015-4498 (bsc#943558)
Add-on notification bypass through data URLs It also includes fixes from the Firefox 38.2.0ESR release:
MFSA 2015-79/CVE-2015-4473/CVE-2015-4474 Miscellaneous memory safety hazards (rv:40.0 / rv:38.2)
MFSA 2015-80/CVE-2015-4475 Out-of-bounds read with malformed MP3 file MFSA 2015-82/CVE-2015-4478 Redefinition of non-configurable JavaScript object properties MFSA 2015-83/CVE-2015-4479 Overflow issues in libstagefright MFSA 2015-87/CVE-2015-4484 Crash when using shared memory in JavaScript MFSA 2015-88/CVE-2015-4491 Heap overflow in gdk-pixbuf when scaling bitmap images MFSA 2015-89/CVE-2015-4485/CVE-2015-4486 Buffer overflows on Libvpx when decoding WebM video MFSA 2015-90/CVE-2015-4487/CVE-2015-4488/CVE-2015-4489 Vulnerabilities found through code inspection MFSA 2015-92/CVE-2015-4492 Use-after-free in XMLHttpRequest with shared workers Security Issues:
CVE-2015-4473 CVE-2015-4474 CVE-2015-4475 CVE-2015-4478 CVE-2015-4479 CVE-2015-4484 CVE-2015-4485 CVE-2015-4486 CVE-2015-4487 CVE-2015-4488 CVE-2015-4489 CVE-2015-4491 CVE-2015-4492 CVE-2015-4497 CVE-2015-4498 CVE-2015-4500 CVE-2015-4501 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.4.0esr~0.7.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~38~0.5.3", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.4.0esr~0.7.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.10.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.19.2.1~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.19.2.1~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.19.2.1~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.19.2.1~0.5.1", rls:"SLES10.0SP4"))) {
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
