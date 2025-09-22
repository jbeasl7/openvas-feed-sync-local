# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856975");
  script_cve_id("CVE-2024-0131", "CVE-2024-0147", "CVE-2024-0149", "CVE-2024-0150", "CVE-2024-53869");
  script_tag(name:"creation_date", value:"2025-01-22 05:01:24 +0000 (Wed, 22 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0207-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0207-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250207-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235871");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020182.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-open-driver-G06-signed' package(s) announced via the SUSE-SU-2025:0207-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nvidia-open-driver-G06-signed fixes the following issues:

- Update to 550.144.03 (bsc#1235461, bsc#1235871)
 * fixes CVE-2024-0131, CVE-2024-0147, CVE-2024-0149,
 CVE-2024-0150, CVE-2024-53869");

  script_tag(name:"affected", value:"'nvidia-open-driver-G06-signed' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06-cuda", rpm:"kernel-firmware-nvidia-gspx-G06-cuda~565.57.01~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nv-prefer-signed-open-driver", rpm:"nv-prefer-signed-open-driver~565.57.01~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~550.144.03~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-azure-devel", rpm:"nvidia-open-driver-G06-signed-azure-devel~550.144.03~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-64kb-devel", rpm:"nvidia-open-driver-G06-signed-cuda-64kb-devel~565.57.01~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-azure-devel", rpm:"nvidia-open-driver-G06-signed-cuda-azure-devel~565.57.01~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-default-devel", rpm:"nvidia-open-driver-G06-signed-cuda-default-devel~565.57.01~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-64kb~565.57.01_k6.4.0_150600.21~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-azure", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-azure~565.57.01_k6.4.0_150600.6~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-default", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-default~565.57.01_k6.4.0_150600.21~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~550.144.03~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~550.144.03_k6.4.0_150600.21~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure", rpm:"nvidia-open-driver-G06-signed-kmp-azure~550.144.03_k6.4.0_150600.6~150600.3.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~550.144.03_k6.4.0_150600.21~150600.3.29.2", rls:"openSUSELeap15.6"))) {
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
