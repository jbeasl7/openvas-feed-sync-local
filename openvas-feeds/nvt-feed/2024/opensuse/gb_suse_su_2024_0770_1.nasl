# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833305");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-42265", "CVE-2024-0074", "CVE-2024-0075");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-12 16:54:32 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-03-08 02:00:51 +0000 (Fri, 08 Mar 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2024:0770-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0770-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YFZHMPNEJOXMXVXXUK4D7WPRRKBSWLEI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2024:0770-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware-nvidia-gspx-G06, nvidia-open-driver-G06-signed
  fixes the following issues:

  Update to 550.54.14

  * Added vGPU Host and vGPU Guest support. For vGPU Host, please refer to the
      README.vgpu packaged in the vGPU Host Package for more details.

  Security issues fixed:

  * CVE-2024-0074: A user could trigger a NULL ptr dereference.

  * CVE-2024-0075: A user could overwrite the end of a buffer, leading to
      crashes or code execution.

  * CVE-2022-42265: A unprivileged user could trigger an integer overflow which
      could lead to crashes or code execution.

  * create /run/udev/static_node-tags/uaccess/nvidia${devid} symlinks also
      during modprobing the nvidia module  this changes the issue of not having
      access to /dev/nvidia${devid}, when gfxcard has been replaced by a different
      gfx card after installing the driver

  * provide nvidia-open-driver-G06-kmp (jsc#PED-7117)

  * this makes it easy to replace the package from nVidia's CUDA repository with
      this presigned package

  ##");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06", rpm:"kernel-firmware-nvidia-gspx-G06~550.54.14~150400.9.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo~550.54.14_k5.14.21_150400.14.75~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure", rpm:"nvidia-open-driver-G06-signed-kmp-azure~550.54.14_k5.14.21_150400.14.75~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-azure-devel", rpm:"nvidia-open-driver-G06-signed-azure-devel~550.54.14~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-debugsource", rpm:"nvidia-open-driver-G06-signed-debugsource~550.54.14~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~550.54.14~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-default-debuginfo~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~550.54.14~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06", rpm:"kernel-firmware-nvidia-gspx-G06~550.54.14~150400.9.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo~550.54.14_k5.14.21_150400.14.75~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure", rpm:"nvidia-open-driver-G06-signed-kmp-azure~550.54.14_k5.14.21_150400.14.75~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-azure-devel", rpm:"nvidia-open-driver-G06-signed-azure-devel~550.54.14~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-debugsource", rpm:"nvidia-open-driver-G06-signed-debugsource~550.54.14~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~550.54.14~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-default-debuginfo~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~550.54.14~150400.9.50.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~550.54.14_k5.14.21_150400.24.108~150400.9.50.1", rls:"openSUSELeap15.4"))) {
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