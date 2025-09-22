# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833280");
  script_version("2025-03-12T05:38:19+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:16 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for installation (SUSE-SU-2023:2826-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2826-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/32WUBNSXRZI46FE4F4EOOUPITVI7YHLX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'installation'
  package(s) announced via the SUSE-SU-2023:2826-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of installation-images fixes the following issues:

  * rebuild the package with the new secure boot key (bsc#1209188).");

  script_tag(name:"affected", value:"'installation' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"installation-images-debuginfodeps-SLES", rpm:"installation-images-debuginfodeps-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"install-initrd-SLES", rpm:"install-initrd-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"installation-images-SLES", rpm:"installation-images-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skelcd-installer-SLES", rpm:"skelcd-installer-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skelcd-installer-net-SLES", rpm:"skelcd-installer-net-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tftpboot-installation-SLE-15-SP3-s390x", rpm:"tftpboot-installation-SLE-15-SP3-s390x~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tftpboot-installation-SLE-15-SP3-aarch64", rpm:"tftpboot-installation-SLE-15-SP3-aarch64~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tftpboot-installation-SLE-15-SP3-ppc64le", rpm:"tftpboot-installation-SLE-15-SP3-ppc64le~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tftpboot-installation-SLE-15-SP3-x86_64", rpm:"tftpboot-installation-SLE-15-SP3-x86_64~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"installation-images-debuginfodeps-SLES", rpm:"installation-images-debuginfodeps-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"install-initrd-SLES", rpm:"install-initrd-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"installation-images-SLES", rpm:"installation-images-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skelcd-installer-SLES", rpm:"skelcd-installer-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skelcd-installer-net-SLES", rpm:"skelcd-installer-net-SLES~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tftpboot-installation-SLE-15-SP3-s390x", rpm:"tftpboot-installation-SLE-15-SP3-s390x~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tftpboot-installation-SLE-15-SP3-aarch64", rpm:"tftpboot-installation-SLE-15-SP3-aarch64~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tftpboot-installation-SLE-15-SP3-ppc64le", rpm:"tftpboot-installation-SLE-15-SP3-ppc64le~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tftpboot-installation-SLE-15-SP3-x86_64", rpm:"tftpboot-installation-SLE-15-SP3-x86_64~16.56.15~150300.3.17.19", rls:"openSUSELeap15.3"))) {
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
