# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0429.1");
  script_cve_id("CVE-2022-47930", "CVE-2024-10846", "CVE-2024-11741", "CVE-2024-13484", "CVE-2024-35177", "CVE-2024-3727", "CVE-2024-45336", "CVE-2024-45339", "CVE-2024-45340", "CVE-2024-45341", "CVE-2024-47770", "CVE-2024-50354", "CVE-2024-9312", "CVE-2024-9313", "CVE-2025-0750", "CVE-2025-22865", "CVE-2025-22866", "CVE-2025-22867", "CVE-2025-23216", "CVE-2025-24366", "CVE-2025-24369", "CVE-2025-24371", "CVE-2025-24376", "CVE-2025-24784", "CVE-2025-24786", "CVE-2025-24787", "CVE-2025-24883", "CVE-2025-24884");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-14 15:42:07 +0000 (Tue, 14 May 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0429-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0429-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250429-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020315.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck-vulndb' package(s) announced via the SUSE-SU-2025:0429-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

- Update to version 0.0.20250207T224745 2025-02-07T22:47:45Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3456 CVE-2025-24786 GHSA-9r4c-jwx3-3j76
 * GO-2025-3457 CVE-2025-24787 GHSA-c7w4-9wv8-7x7c
 * GO-2025-3458 CVE-2025-24366 GHSA-vj7w-3m8c-6vpx

- Update to version 0.0.20250206T175003 2025-02-06T17:50:03Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2023-1867 CVE-2022-47930 GHSA-c58h-qv6g-fw74
 * GO-2024-3244 CVE-2024-50354 GHSA-cph5-3pgr-c82g

- Update to version 0.0.20250206T165438 2025-02-06T16:54:38Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3428 CVE-2025-22867
 * GO-2025-3447 CVE-2025-22866

- Update to version 0.0.20250205T232745 2025-02-05T23:27:45Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3408
 * GO-2025-3448 GHSA-23qp-3c2m-xx6w
 * GO-2025-3449 GHSA-mx2j-7cmv-353c
 * GO-2025-3450 GHSA-w7wm-2425-7p2h
 * GO-2025-3454 GHSA-mj4v-hp69-27x5
 * GO-2025-3455 GHSA-vqv5-385r-2hf8

- Update to version 0.0.20250205T003520 2025-02-05T00:35:20Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3451

- Update to version 0.0.20250204T220613 2025-02-04T22:06:13Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3431 CVE-2025-24884 GHSA-hcr5-wv4p-h2g2
 * GO-2025-3433 CVE-2025-23216 GHSA-47g2-qmh2-749v
 * GO-2025-3434 CVE-2025-24376 GHSA-fc89-jghx-8pvg
 * GO-2025-3435 CVE-2025-24784 GHSA-756x-m4mj-q96c
 * GO-2025-3436 CVE-2025-24883 GHSA-q26p-9cq4-7fc2
 * GO-2025-3437 GHSA-274v-mgcv-cm8j
 * GO-2025-3438 CVE-2024-11741 GHSA-wxcc-2f3q-4h58
 * GO-2025-3442 CVE-2025-24371 GHSA-22qq-3xwm-r5x4
 * GO-2025-3443 GHSA-r3r4-g7hq-pq4f
 * GO-2025-3444 CVE-2024-35177
 * GO-2025-3445 CVE-2024-47770

- Use standard RPM macros to unpack the source and populate a
 working directory. Fixes build with RPM 4.20.

- Update to version 0.0.20250130T185858 2025-01-30T18:58:58Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2024-2842 CVE-2024-3727 GHSA-6wvf-f2vw-3425
 * GO-2024-3181 CVE-2024-9313 GHSA-x5q3-c8rm-w787
 * GO-2024-3188 CVE-2024-9312 GHSA-4gfw-wf7c-w6g2
 * GO-2025-3372 CVE-2024-45339 GHSA-6wxm-mpqj-6jpf
 * GO-2025-3373 CVE-2024-45341
 * GO-2025-3383 CVE-2024-45340
 * GO-2025-3408
 * GO-2025-3412 CVE-2024-10846 GHSA-36gq-35j3-p9r9
 * GO-2025-3420 CVE-2024-45336
 * GO-2025-3421 CVE-2025-22865
 * GO-2025-3424 CVE-2025-24369
 * GO-2025-3426 CVE-2025-0750 GHSA-hp5j-2585-qx6g
 * GO-2025-3427 CVE-2024-13484 GHSA-58fx-7v9q-3g56");

  script_tag(name:"affected", value:"'govulncheck-vulndb' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20250207T224745~150000.1.32.1", rls:"openSUSELeap15.6"))) {
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
