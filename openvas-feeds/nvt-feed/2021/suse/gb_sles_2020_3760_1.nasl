# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3760.1");
  script_cve_id("CVE-2020-15106", "CVE-2020-15112", "CVE-2020-15184", "CVE-2020-15185", "CVE-2020-15186", "CVE-2020-15187", "CVE-2020-8565", "CVE-2020-8566");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 15:24:31 +0000 (Fri, 02 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3760-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3760-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203760-1/");
  script_xref(name:"URL", value:"https://documentation.suse.com/suse-caasp/4.2/html/caasp-admin/_cluster_upd");
  script_xref(name:"URL", value:"https://documentation.suse.com/suse-caasp/4.2/html/caasp-admin/_cluster_upd");
  script_xref(name:"URL", value:"https://documentation.suse.com/suse-caasp/4.2/html/caasp-admin/_miscellaneo");
  script_xref(name:"URL", value:"https://www.suse.com/releasenotes/x86_64/SUSE-CAASP/4/#_changes_in_4_2_4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security changes in Kubernetes, and helm, Bugfix in cri-o package, etcd' package(s) announced via the SUSE-SU-2020:3760-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"= Required Actions

== Kubernetes & etcd (Security fixes)

This fix involves an upgrade of Kubernetes and some add-ons. See [link moved to references] ates.html#_updating_kubernetes_components for the upgrade procedure.

== Skuba & helm/helm3

In order to update skuba and helm or helm 3, you need to update the management workstation. See detailed instructions at [link moved to references] ates.html#_update_management_workstation

= Known Issues

Modifying the file `/etc/sysconfig/kubelet` directly is not supported:
documentation at [link moved to references] us.html#_configuring_kubelet

Be sure to check the Release Notes at [link moved to references] for any additional known issues or behavioral changes.");

  script_tag(name:"affected", value:"'Security changes in Kubernetes, and helm, Bugfix in cri-o package, etcd' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise Module for Containers 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-client", rpm:"kubernetes-client~1.17.13~4.21.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes-common", rpm:"kubernetes-common~1.17.13~4.21.2", rls:"SLES15.0SP1"))) {
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
