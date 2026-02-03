# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0338.1");
  script_cve_id("CVE-2025-0838");
  script_tag(name:"creation_date", value:"2026-02-02 04:42:36 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-30 18:10:35 +0000 (Wed, 30 Jul 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0338-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0338-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260338-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237543");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023984.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abseil-cpp' package(s) announced via the SUSE-SU-2026:0338-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for abseil-cpp fixes the following issues:

- CVE-2025-0838: Fixed heap buffer overflow in sized constructors, reserve(), and rehash() methods of absl:{flat,node}hash{set,map} (bsc#1237543).");

  script_tag(name:"affected", value:"'abseil-cpp' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp-devel", rpm:"abseil-cpp-devel~20240116.3~150600.19.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2401_0_0", rpm:"libabsl2401_0_0~20240116.3~150600.19.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2401_0_0-32bit", rpm:"libabsl2401_0_0-32bit~20240116.3~150600.19.6.1", rls:"openSUSELeap15.6"))) {
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
