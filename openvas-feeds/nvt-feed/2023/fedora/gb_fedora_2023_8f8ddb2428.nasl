# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884809");
  script_cve_id("CVE-2023-3676", "CVE-2023-3955");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:31 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 18:29:32 +0000 (Wed, 08 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-8f8ddb2428)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-8f8ddb2428");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-8f8ddb2428");
  script_xref(name:"URL", value:"https://copr.fedorainfracloud.org/coprs/buckaroogeek/copr-k8s-1.25/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes' package(s) announced via the FEDORA-2023-8f8ddb2428 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updates to Kubernetes for F38 and F39. Security fixes for CVE-2023-3955 and CVE-2023-3676. Related update for rawhide already in stable. Update for F37 is currently in COPR at [link moved to references] due to golang blocker.");

  script_tag(name:"affected", value:"'kubernetes' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"kubernetes", rpm:"kubernetes~1.27.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-client", rpm:"kubernetes-client~1.27.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-kubeadm", rpm:"kubernetes-kubeadm~1.27.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-master", rpm:"kubernetes-master~1.27.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-node", rpm:"kubernetes-node~1.27.5~1.fc39", rls:"FC39"))) {
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
