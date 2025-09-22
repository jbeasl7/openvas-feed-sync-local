# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1476.1");
  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4495", "CVE-2015-4497", "CVE-2015-4498");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 17:23:00 +0000 (Fri, 28 Jun 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1476-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151476-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943608");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-September/001562.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nss' package(s) announced via the SUSE-SU-2015:1476-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to version 38.2.1 ESR to fix several critical and non critical security vulnerabilities.

- Firefox was updated to 38.2.1 ESR (bsc#943608)
 * MFSA 2015-94/CVE-2015-4497 (bsc#943557)
 Use-after-free when resizing canvas element during restyling
 * MFSA 2015-95/CVE-2015-4498 (bsc#943558)
 Add-on notification bypass through data URLs

- Firefox was updated to 38.2.0 ESR (bsc#940806)
 * MFSA 2015-78/CVE-2015-4495
 (bmo#1178058, bmo#1179262)
 Same origin violation and local file stealing via PDF reader
 * MFSA 2015-79/CVE-2015-4473/CVE-2015-4474
 (bmo#1143130, bmo#1161719, bmo#1177501, bmo#1181204,
 bmo#1184068, bmo#1188590, bmo#1146213, bmo#1178890,
 bmo#1182711)
 Miscellaneous memory safety hazards (rv:40.0 / rv:38.2)
 * MFSA 2015-80/CVE-2015-4475
 (bmo#1175396)
 Out-of-bounds read with malformed MP3 file
 * MFSA 2015-82/CVE-2015-4478
 (bmo#1105914)
 Redefinition of non-configurable JavaScript object properties
 * MFSA 2015-83/CVE-2015-4479
 (bmo#1185115, bmo#1144107, bmo#1170344, bmo#1186718)
 Overflow issues in libstagefright
 * MFSA 2015-87/CVE-2015-4484
 (bmo#1171540)
 Crash when using shared memory in JavaScript
 * MFSA 2015-88/CVE-2015-4491
 (bmo#1184009)
 Heap overflow in gdk-pixbuf when scaling bitmap images
 * MFSA 2015-89/CVE-2015-4485/CVE-2015-4486
 (bmo#1177948, bmo#1178148)
 Buffer overflows on Libvpx when decoding WebM video
 * MFSA 2015-90/CVE-2015-4487/CVE-2015-4488/CVE-2015-4489
 (bmo#1176270, bmo#1182723, bmo#1171603)
 Vulnerabilities found through code inspection
 * MFSA 2015-92/CVE-2015-4492
 (bmo#1185820)
 Use-after-free in XMLHttpRequest with shared workers

Mozilla NSS switched the CKBI ABI from 1.98 to 2.4, which is what Firefox 38ESR uses.");

  script_tag(name:"affected", value:"'MozillaFirefox, mozilla-nss' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.2.1esr~45.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~31.0~14.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.2.1esr~45.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.19.2.0~26.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.19.2.0~26.2", rls:"SLES12.0"))) {
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
