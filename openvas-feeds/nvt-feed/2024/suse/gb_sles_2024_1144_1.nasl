# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1144.1");
  script_cve_id("CVE-2024-1753");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 15:15:41 +0000 (Mon, 18 Mar 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1144-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241144-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221677");
  script_xref(name:"URL", value:"https://github.com/containers/buildah/releases/tag/v1.30.0");
  script_xref(name:"URL", value:"https://github.com/containers/buildah/releases/tag/v1.31.0");
  script_xref(name:"URL", value:"https://github.com/containers/buildah/releases/tag/v1.32.0");
  script_xref(name:"URL", value:"https://github.com/containers/buildah/releases/tag/v1.33.0");
  script_xref(name:"URL", value:"https://github.com/containers/buildah/releases/tag/v1.34.0");
  script_xref(name:"URL", value:"https://github.com/containers/buildah/releases/tag/v1.34.1");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/034878.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah' package(s) announced via the SUSE-SU-2024:1144-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

- CVE-2024-1753: Fixed an issue to prevent a full container escape at build time. (bsc#1221677)
- Update to version 1.34.1 for compatibility with Docker 25.0
 (which is not in SLES yet, but will eventually be) (bsc#1219563).
 See the corresponding release notes:
 * [links moved to references]

- Require cni-plugins (bsc#1220568)");

  script_tag(name:"affected", value:"'buildah' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"cni", rpm:"cni~0.7.1~150100.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cni-plugins", rpm:"cni-plugins~0.8.6~150100.3.22.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"cni", rpm:"cni~0.7.1~150100.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cni-plugins", rpm:"cni-plugins~0.8.6~150100.3.22.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.34.1~150400.3.27.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cni", rpm:"cni~0.7.1~150100.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cni-plugins", rpm:"cni-plugins~0.8.6~150100.3.22.3", rls:"SLES15.0SP4"))) {
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
