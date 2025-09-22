# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0334.1");
  script_cve_id("CVE-2021-41089", "CVE-2021-41091", "CVE-2021-41092", "CVE-2021-41103", "CVE-2021-41190");
  script_tag(name:"creation_date", value:"2022-02-05 03:21:38 +0000 (Sat, 05 Feb 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-14 19:38:38 +0000 (Thu, 14 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0334-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0334-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220334-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker' package(s) announced via the SUSE-SU-2022:0334-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker fixes the following issues:

CVE-2021-41089: Fixed 'cp' can chmod host files (bsc#1191015).

CVE-2021-41091: Fixed flaw that could lead to data directory traversal
 in moby (bsc#1191434).

CVE-2021-41092: Fixed exposed user credentials with a misconfigured
 configuration file (bsc#1191334).

CVE-2021-41103: Fixed file access to local users in containerd
 (bsc#1191121).

CVE-2021-41190: Fixed OCI manifest and index parsing confusion
 (bsc#1193273).");

  script_tag(name:"affected", value:"'containerd, docker' package(s) on SUSE Linux Enterprise Micro 5.0, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Module for Containers 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.4.12~60.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.12_ce~159.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.12_ce~159.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.12_ce~159.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~20.10.12_ce~159.1", rls:"SLES15.0SP3"))) {
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
