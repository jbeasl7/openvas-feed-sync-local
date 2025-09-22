# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.854876");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-08-04 01:04:52 +0000 (Thu, 04 Aug 2022)");
  script_name("openSUSE: Security Advisory for drbd (SUSE-SU-2022:2656-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2656-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B6OOYCIJBUT3JW7XZN77BJ6JVLGSP3ER");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drbd'
  package(s) announced via the SUSE-SU-2022:2656-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of drbd fixes the following issue:

  - rebuild with new secure boot key due to grub2 boothole 3 issues
       (bsc#1198581)");

  script_tag(name:"affected", value:"'drbd' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"drbd-9.0.30", rpm:"drbd-9.0.30~1+git.10bee2d5~150400.3.2.9", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-debugsource-9.0.30", rpm:"drbd-debugsource-9.0.30~1+git.10bee2d5~150400.3.2.9", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-default-9.0.30", rpm:"drbd-kmp-default-9.0.30~1+git.10bee2d5_k5.14.21_150400.24.11~150400.3.2.9", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-default-debuginfo-9.0.30", rpm:"drbd-kmp-default-debuginfo-9.0.30~1+git.10bee2d5_k5.14.21_150400.24.11~150400.3.2.9", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-64kb-9.0.30", rpm:"drbd-kmp-64kb-9.0.30~1+git.10bee2d5_k5.14.21_150400.24.11~150400.3.2.9", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-64kb-debuginfo-9.0.30", rpm:"drbd-kmp-64kb-debuginfo-9.0.30~1+git.10bee2d5_k5.14.21_150400.24.11~150400.3.2.9", rls:"openSUSELeap15.4"))) {
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
