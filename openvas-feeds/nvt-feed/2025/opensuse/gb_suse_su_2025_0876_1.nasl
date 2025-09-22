# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0876.1");
  script_tag(name:"creation_date", value:"2025-03-19 04:05:51 +0000 (Wed, 19 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0876-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0876-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250876-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020522.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck-vulndb' package(s) announced via the SUSE-SU-2025:0876-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

- Update to version 0.0.20250313T170021 2025-03-13T17:00:21Z (jsc#PED-11136)
 * GO-2025-3427
 * GO-2025-3442
 * GO-2025-3443
 * GO-2025-3508
 * GO-2025-3509
 * GO-2025-3510
 * GO-2025-3511
 * GO-2025-3512
 * GO-2025-3514
 * GO-2025-3515

- Update to version 0.0.20250312T181707 2025-03-12T18:17:07Z (jsc#PED-11136):
 * GO-2025-3459
 * GO-2025-3460
 * GO-2025-3461
 * GO-2025-3462
 * GO-2025-3463
 * GO-2025-3465
 * GO-2025-3466
 * GO-2025-3467
 * GO-2025-3468
 * GO-2025-3470
 * GO-2025-3472
 * GO-2025-3474
 * GO-2025-3475
 * GO-2025-3476
 * GO-2025-3477
 * GO-2025-3479
 * GO-2025-3480
 * GO-2025-3481
 * GO-2025-3482
 * GO-2025-3483
 * GO-2025-3484
 * GO-2025-3485
 * GO-2025-3489
 * GO-2025-3490
 * GO-2025-3491
 * GO-2025-3492
 * GO-2025-3494
 * GO-2025-3495
 * GO-2025-3498
 * GO-2025-3499
 * GO-2025-3500
 * GO-2025-3503
 * GO-2025-3504
 * GO-2025-3505
 * GO-2025-3507");

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

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20250313T170021~150000.1.40.1", rls:"openSUSELeap15.6"))) {
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
