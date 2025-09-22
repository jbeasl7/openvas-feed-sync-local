# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856916");
  script_cve_id("CVE-2024-12678", "CVE-2024-25131", "CVE-2024-25133", "CVE-2024-28892", "CVE-2024-43803", "CVE-2024-45338", "CVE-2024-45387", "CVE-2024-54148", "CVE-2024-55196", "CVE-2024-55947", "CVE-2024-56362", "CVE-2024-56513", "CVE-2024-56514", "CVE-2024-9779", "CVE-2025-21609", "CVE-2025-21613", "CVE-2025-21614", "CVE-2025-22130");
  script_tag(name:"creation_date", value:"2025-01-11 05:00:54 +0000 (Sat, 11 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-21 15:15:29 +0000 (Thu, 21 Nov 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0060-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0060-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250060-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020087.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck-vulndb' package(s) announced via the SUSE-SU-2025:0060-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

- Update to version 0.0.20250108T191942 2025-01-08T19:19:42Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3371 GHSA-2r2v-9pf8-6342
 * GO-2025-3374 CVE-2025-22130 GHSA-j4jw-m6xr-fv6c

- Update to version 0.0.20250107T160406 2025-01-07T16:04:06Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3363 GO-2025-3364 GO-2025-3367 GO-2025-3368
 * GO-2024-3355 CVE-2024-54148 GHSA-r7j8-5h9c-f6fx
 * GO-2024-3356 CVE-2024-55947 GHSA-qf5v-rp47-55gg
 * GO-2024-3357 CVE-2024-56362 GHSA-xwx7-p63r-2rj8
 * GO-2024-3358 CVE-2024-45387 GHSA-vq94-9pfv-ccqr
 * GO-2024-3359 CVE-2024-28892 GHSA-5qww-56gc-f66c
 * GO-2024-3360 CVE-2024-25133 GHSA-wgqq-9qh8-wvqv
 * GO-2025-3361 CVE-2024-55196 GHSA-rv83-h68q-c4wq
 * GO-2025-3362 CVE-2025-21609 GHSA-8fx8-pffw-w498
 * GO-2025-3363 CVE-2024-56514 GHSA-cwrh-575j-8vr3
 * GO-2025-3364 CVE-2024-56513 GHSA-mg7w-c9x2-xh7r
 * GO-2025-3367 CVE-2025-21614 GHSA-r9px-m959-cxf4
 * GO-2025-3368 CVE-2025-21613 GHSA-v725-9546-7q7m

- Update to version 0.0.20241220T214820 2024-12-20T21:48:20Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2024-3101 GHSA-75qh-gg76-p2w4
 * GO-2024-3339 GHSA-8wcc-m6j2-qxvm

- Update to version 0.0.20241220T203729 2024-12-20T20:37:29Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2024-3101 GHSA-75qh-gg76-p2w4
 * GO-2024-3109 CVE-2024-43803 GHSA-pqfh-xh7w-7h3p
 * GO-2024-3333 CVE-2024-45338 GHSA-w32m-9786-jp63
 * GO-2024-3342 GHSA-hxr6-2p24-hf98
 * GO-2024-3343 CVE-2024-9779 GHSA-jhh6-6fhp-q2xp
 * GO-2024-3344 GHSA-32gq-x56h-299c
 * GO-2024-3349 CVE-2024-25131 GHSA-77c2-c35q-254w
 * GO-2024-3350 GHSA-5pf6-cq2v-23ww
 * GO-2024-3354 CVE-2024-12678 GHSA-hr68-hvgv-xxqf");

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

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20250108T191942~150000.1.26.1", rls:"openSUSELeap15.6"))) {
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
