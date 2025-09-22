# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0217.1");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0217-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0217-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250217-1.html");
  script_xref(name:"URL", value:"https://github.com/kubevirt/containerized-data-importer/releases/tag/v1.60.2");
  script_xref(name:"URL", value:"https://github.com/kubevirt/containerized-data-importer/releases/tag/v1.60.3");
  script_xref(name:"URL", value:"https://github.com/kubevirt/containerized-data-importer/releases/tag/v1.60.4");
  script_xref(name:"URL", value:"https://github.com/kubevirt/containerized-data-importer/releases/tag/v1.61.0");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020187.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cdi-apiserver-container, cdi-cloner-container, cdi-controller-container, cdi-importer-container, cdi-operator-container, cdi-uploadproxy-container, cdi-uploadserver-container, containerized-data-importer' package(s) announced via the SUSE-SU-2025:0217-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cdi-apiserver-container, cdi-cloner-container, cdi-controller-container, cdi-importer-container, cdi-operator-container, cdi-uploadproxy-container, cdi-uploadserver-container, containerized-data-importer fixes the following issues:

Update to version 1.61.0:

* Release notes

 - [links moved to references]

- Enable aarch64 build for SLE and mark it as techpreview (jsc#PED-10545)
- Install nbdkit-server to avoid pulling unneeded dependencies");

  script_tag(name:"affected", value:"'cdi-apiserver-container, cdi-cloner-container, cdi-controller-container, cdi-importer-container, cdi-operator-container, cdi-uploadproxy-container, cdi-uploadserver-container, containerized-data-importer' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-api", rpm:"containerized-data-importer-api~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-cloner", rpm:"containerized-data-importer-cloner~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-controller", rpm:"containerized-data-importer-controller~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-importer", rpm:"containerized-data-importer-importer~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-manifests", rpm:"containerized-data-importer-manifests~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-operator", rpm:"containerized-data-importer-operator~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-uploadproxy", rpm:"containerized-data-importer-uploadproxy~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-uploadserver", rpm:"containerized-data-importer-uploadserver~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-cdi_containers_meta", rpm:"obs-service-cdi_containers_meta~1.61.0~150600.3.12.1", rls:"openSUSELeap15.6"))) {
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
