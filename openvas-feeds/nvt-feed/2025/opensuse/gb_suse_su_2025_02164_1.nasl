# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02164.1");
  script_cve_id("CVE-2025-48797", "CVE-2025-48798");
  script_tag(name:"creation_date", value:"2025-07-02 04:12:24 +0000 (Wed, 02 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-27 14:15:24 +0000 (Tue, 27 May 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02164-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02164-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502164-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243712");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040546.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp' package(s) announced via the SUSE-SU-2025:02164-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gimp fixes the following issues:

- CVE-2025-48797: Fixed two buffer over-reads and one heap-based buffer overflow in its TGA parser (bsc#1243711).
- CVE-2025-48798: Fixed two use-after-free bugs and one double free bug in its XCF parser (bsc#1243712).");

  script_tag(name:"affected", value:"'gimp' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.10.30~150400.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.10.30~150400.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-lang", rpm:"gimp-lang~2.10.30~150400.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugin-aa", rpm:"gimp-plugin-aa~2.10.30~150400.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0", rpm:"libgimp-2_0-0~2.10.30~150400.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-32bit", rpm:"libgimp-2_0-0-32bit~2.10.30~150400.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0", rpm:"libgimpui-2_0-0~2.10.30~150400.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-32bit", rpm:"libgimpui-2_0-0-32bit~2.10.30~150400.3.20.1", rls:"openSUSELeap15.6"))) {
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
