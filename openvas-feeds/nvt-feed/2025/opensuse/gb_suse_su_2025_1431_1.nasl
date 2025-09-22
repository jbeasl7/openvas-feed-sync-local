# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1431.1");
  script_tag(name:"creation_date", value:"2025-05-05 04:07:29 +0000 (Mon, 05 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1431-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1431-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251431-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039128.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck-vulndb' package(s) announced via the SUSE-SU-2025:1431-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

- Update to version 0.0.20250424T181457 (jsc#PED-11136)
 * GO-2025-3603
 * GO-2025-3604
 * GO-2025-3607
 * GO-2025-3608
 * GO-2025-3609
 * GO-2025-3610
 * GO-2025-3611
 * GO-2025-3612
 * GO-2025-3615
 * GO-2025-3618
 * GO-2025-3619
 * GO-2025-3620
 * GO-2025-3621
 * GO-2025-3622
 * GO-2025-3623
 * GO-2025-3625
 * GO-2025-3627
 * GO-2025-3630
 * GO-2025-3631
 * GO-2025-3632
 * GO-2025-3633
 * GO-2025-3634
 * GO-2025-3635
 * GO-2025-3636
 * GO-2025-3637
 * GO-2025-3638
 * GO-2025-3639
 * GO-2025-3640
 * GO-2025-3642
 * GO-2025-3643
 * GO-2025-3644");

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

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20250424T181457~150000.1.68.1", rls:"openSUSELeap15.6"))) {
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
