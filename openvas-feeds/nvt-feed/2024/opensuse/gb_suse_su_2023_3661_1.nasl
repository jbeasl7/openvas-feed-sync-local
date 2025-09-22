# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833450");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-4039");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 20:01:22 +0000 (Thu, 14 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:10 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for gcc12 (SUSE-SU-2023:3661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3661-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WDRPMTNOYKHA3MXYTO3OBMMUHDR6SDPO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc12'
  package(s) announced via the SUSE-SU-2023:3661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc12 fixes the following issues:

  * CVE-2023-4039: Fixed incorrect stack protector for C99 VLAs on Aarch64
      (bsc#1214052).

  ##");

  script_tag(name:"affected", value:"'gcc12' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc12", rpm:"libstdc++6-devel-gcc12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-ada", rpm:"gcc12-ada~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-fortran-debuginfo", rpm:"gcc12-fortran-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2", rpm:"libtsan2~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2-debuginfo", rpm:"libtsan2-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-c++-debuginfo", rpm:"gcc12-c++-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-testresults", rpm:"gcc12-testresults~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-c++", rpm:"gcc12-c++~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp", rpm:"libstdc++6-pp~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo21", rpm:"libgo21~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-go-debuginfo", rpm:"gcc12-go-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada12-debuginfo", rpm:"libada12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-obj-c++", rpm:"gcc12-obj-c++~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-objc-debuginfo", rpm:"gcc12-objc-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-debugsource", rpm:"gcc12-debugsource~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo21-debuginfo", rpm:"libgo21-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-ada-debuginfo", rpm:"gcc12-ada-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada12", rpm:"libada12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-PIE", rpm:"gcc12-PIE~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp12-debuginfo", rpm:"cpp12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-fortran", rpm:"gcc12-fortran~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-debuginfo", rpm:"gcc12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-objc", rpm:"gcc12-objc~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-obj-c++-debuginfo", rpm:"gcc12-obj-c++-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12", rpm:"gcc12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-go", rpm:"gcc12-go~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp12", rpm:"cpp12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-debuginfo", rpm:"libasan8-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8", rpm:"libasan8~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-locale", rpm:"gcc12-locale~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo21-32bit-debuginfo", rpm:"libgo21-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime3-32bit-debuginfo", rpm:"libgdruntime3-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc12", rpm:"cross-nvptx-gcc12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit", rpm:"libasan8-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime3-32bit", rpm:"libgdruntime3-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit-debuginfo", rpm:"libasan8-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-ada-32bit", rpm:"gcc12-ada-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc12-32bit", rpm:"libstdc++6-devel-gcc12-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-obj-c++-32bit", rpm:"gcc12-obj-c++-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-d-32bit", rpm:"gcc12-d-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo21-32bit", rpm:"libgo21-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-32bit", rpm:"gcc12-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-32bit", rpm:"libstdc++6-pp-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc12-debugsource", rpm:"cross-nvptx-gcc12-debugsource~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc12-debuginfo", rpm:"cross-nvptx-gcc12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-objc-32bit", rpm:"gcc12-objc-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-go-32bit", rpm:"gcc12-go-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos3-32bit-debuginfo", rpm:"libgphobos3-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-c++-32bit", rpm:"gcc12-c++-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos3-32bit", rpm:"libgphobos3-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-fortran-32bit", rpm:"gcc12-fortran-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada12-32bit", rpm:"libada12-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada12-32bit-debuginfo", rpm:"libada12-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib12-devel", rpm:"cross-nvptx-newlib12-devel~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-d-debuginfo", rpm:"gcc12-d-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime3-debuginfo", rpm:"libgdruntime3-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos3", rpm:"libgphobos3~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos3-debuginfo", rpm:"libgphobos3-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-d", rpm:"gcc12-d~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime3", rpm:"libgdruntime3~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-info", rpm:"gcc12-info~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0", rpm:"libhwasan0~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0-debuginfo", rpm:"libhwasan0-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc12", rpm:"libstdc++6-devel-gcc12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-ada", rpm:"gcc12-ada~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-fortran-debuginfo", rpm:"gcc12-fortran-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2", rpm:"libtsan2~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2-debuginfo", rpm:"libtsan2-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-c++-debuginfo", rpm:"gcc12-c++-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-testresults", rpm:"gcc12-testresults~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-c++", rpm:"gcc12-c++~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp", rpm:"libstdc++6-pp~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo21", rpm:"libgo21~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-go-debuginfo", rpm:"gcc12-go-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada12-debuginfo", rpm:"libada12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-obj-c++", rpm:"gcc12-obj-c++~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-objc-debuginfo", rpm:"gcc12-objc-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-debugsource", rpm:"gcc12-debugsource~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo21-debuginfo", rpm:"libgo21-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-ada-debuginfo", rpm:"gcc12-ada-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada12", rpm:"libada12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-PIE", rpm:"gcc12-PIE~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp12-debuginfo", rpm:"cpp12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-fortran", rpm:"gcc12-fortran~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-debuginfo", rpm:"gcc12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-objc", rpm:"gcc12-objc~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-obj-c++-debuginfo", rpm:"gcc12-obj-c++-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12", rpm:"gcc12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-go", rpm:"gcc12-go~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp12", rpm:"cpp12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-debuginfo", rpm:"libasan8-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8", rpm:"libasan8~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-locale", rpm:"gcc12-locale~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo21-32bit-debuginfo", rpm:"libgo21-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime3-32bit-debuginfo", rpm:"libgdruntime3-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc12", rpm:"cross-nvptx-gcc12~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit", rpm:"libasan8-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime3-32bit", rpm:"libgdruntime3-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit-debuginfo", rpm:"libasan8-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-ada-32bit", rpm:"gcc12-ada-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc12-32bit", rpm:"libstdc++6-devel-gcc12-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-obj-c++-32bit", rpm:"gcc12-obj-c++-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-d-32bit", rpm:"gcc12-d-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo21-32bit", rpm:"libgo21-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-32bit", rpm:"gcc12-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-32bit", rpm:"libstdc++6-pp-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc12-debugsource", rpm:"cross-nvptx-gcc12-debugsource~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc12-debuginfo", rpm:"cross-nvptx-gcc12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-objc-32bit", rpm:"gcc12-objc-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-go-32bit", rpm:"gcc12-go-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos3-32bit-debuginfo", rpm:"libgphobos3-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-c++-32bit", rpm:"gcc12-c++-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos3-32bit", rpm:"libgphobos3-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-fortran-32bit", rpm:"gcc12-fortran-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada12-32bit", rpm:"libada12-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada12-32bit-debuginfo", rpm:"libada12-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib12-devel", rpm:"cross-nvptx-newlib12-devel~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-d-debuginfo", rpm:"gcc12-d-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime3-debuginfo", rpm:"libgdruntime3-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos3", rpm:"libgphobos3~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos3-debuginfo", rpm:"libgphobos3-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-d", rpm:"gcc12-d~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime3", rpm:"libgdruntime3~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-info", rpm:"gcc12-info~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0", rpm:"libhwasan0~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0-debuginfo", rpm:"libhwasan0-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-debugsource", rpm:"gcc12-debugsource~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-debuginfo", rpm:"gcc12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-debugsource", rpm:"gcc12-debugsource~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc12-debuginfo", rpm:"gcc12-debuginfo~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~12.3.0+git1204~150000.1.16.1", rls:"openSUSELeapMicro5.4"))) {
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