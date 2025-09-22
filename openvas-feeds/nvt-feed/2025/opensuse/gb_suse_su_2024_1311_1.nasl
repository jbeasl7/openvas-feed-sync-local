# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.1311.1");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1311-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241311-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222699");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-April/018361.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubevirt, virt-api-container, virt-controller-container, virt-exportproxy-container, virt-exportserver-container, virt-handler-container, virt-launcher-container, virt-libguestfs-tools-container, virt-operator-container, virt-pr-helper-container' package(s) announced via the SUSE-SU-2024:1311-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubevirt, virt-api-container, virt-controller-container, virt-exportproxy-container, virt-exportserver-container, virt-handler-container, virt-launcher-container, virt-libguestfs-tools-container, virt-operator-container, virt-pr-helper-container fixes the following issues:

- Improve the OrdinalPodInterfaceName mechanism (bsc#1222699)

Also containers were rebuilt against the current released updates.");

  script_tag(name:"affected", value:"'kubevirt, virt-api-container, virt-controller-container, virt-exportproxy-container, virt-exportserver-container, virt-handler-container, virt-launcher-container, virt-libguestfs-tools-container, virt-operator-container, virt-pr-helper-container' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-container-disk", rpm:"kubevirt-container-disk~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-manifests", rpm:"kubevirt-manifests~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-tests", rpm:"kubevirt-tests~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-api", rpm:"kubevirt-virt-api~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-controller", rpm:"kubevirt-virt-controller~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-exportproxy", rpm:"kubevirt-virt-exportproxy~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-exportserver", rpm:"kubevirt-virt-exportserver~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-handler", rpm:"kubevirt-virt-handler~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-launcher", rpm:"kubevirt-virt-launcher~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-operator", rpm:"kubevirt-virt-operator~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virtctl", rpm:"kubevirt-virtctl~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-kubevirt_containers_meta", rpm:"obs-service-kubevirt_containers_meta~1.1.1~150500.8.15.1", rls:"openSUSELeap15.5"))) {
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
