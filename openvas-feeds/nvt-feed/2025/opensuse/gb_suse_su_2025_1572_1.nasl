# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1572.1");
  script_cve_id("CVE-2025-43961", "CVE-2025-43962", "CVE-2025-43963", "CVE-2025-43964");
  script_tag(name:"creation_date", value:"2025-05-22 12:05:52 +0000 (Thu, 22 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-08 16:54:54 +0000 (Thu, 08 May 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1572-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1572-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251572-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241643");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-May/020837.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw' package(s) announced via the SUSE-SU-2025:1572-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libraw fixes the following issues:

- CVE-2025-43961: Fixed out-of-bounds read in the Fujifilm 0xf00c tag parser in metadata/tiff.cpp (bsc#1241643)
- CVE-2025-43962: Fixed out-of-bounds read when tag 0x412 processing in phase_one_correct function (bsc#1241585)
- CVE-2025-43963: Fixed out-of-buffer access during phase_one_correct in decoders/load_mfbacks.cpp (bsc#1241642)
- CVE-2025-43964: Fixed tag 0x412 processing in phase_one_correct does not enforce minimum w0 and w1 values (bsc#1241584)");

  script_tag(name:"affected", value:"'libraw' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.21.1~150600.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-devel-static", rpm:"libraw-devel-static~0.21.1~150600.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.21.1~150600.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw23", rpm:"libraw23~0.21.1~150600.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw23-32bit", rpm:"libraw23-32bit~0.21.1~150600.3.5.1", rls:"openSUSELeap15.6"))) {
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
