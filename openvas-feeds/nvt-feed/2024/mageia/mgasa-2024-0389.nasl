# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0389");
  script_cve_id("CVE-2024-10220", "CVE-2024-3177");
  script_tag(name:"creation_date", value:"2024-12-09 04:12:07 +0000 (Mon, 09 Dec 2024)");
  script_version("2024-12-10T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-12-10 05:05:39 +0000 (Tue, 10 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0389)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0389");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0389.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33143");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33802");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WL54MTLGMTBZZO5PYGEGEBERTMADC4WC/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/11/20/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes' package(s) announced via the MGASA-2024-0389 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A security issue was discovered in Kubernetes where users may be able to
launch containers that bypass the mountable secrets policy enforced by
the ServiceAccount admission plugin when using containers, init
containers, and ephemeral containers with the envFrom field populated.
The policy ensures pods running with a service account may only
reference secrets specified in the service account's secrets field.
Kubernetes clusters are only affected if the ServiceAccount admission
plugin and the kubernetes.io/enforce-mountable-secrets annotation are
used together with containers, init containers, and ephemeral containers
with the envFrom field populated. CVE-2024-3177
The Kubernetes kubelet component allows arbitrary command execution via
specially crafted gitRepo volumes. CVE-2024-10220");

  script_tag(name:"affected", value:"'kubernetes' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"kubernetes", rpm:"kubernetes~1.27.16~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-client", rpm:"kubernetes-client~1.27.16~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-kubeadm", rpm:"kubernetes-kubeadm~1.27.16~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-master", rpm:"kubernetes-master~1.27.16~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-node", rpm:"kubernetes-node~1.27.16~2.mga9", rls:"MAGEIA9"))) {
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
