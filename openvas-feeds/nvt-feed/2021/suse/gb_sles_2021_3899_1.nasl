# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3899.1");
  script_tag(name:"creation_date", value:"2021-12-05 03:20:52 +0000 (Sun, 05 Dec 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3899-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3899-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213899-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192248");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-December/009830.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aaa_base' package(s) announced via the SUSE-SU-2021:3899-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for aaa_base fixes the following issues:

- Allowed ping and ICMP commands without CAP_NET_RAW (bsc#1174504).
- Add $HOME/.local/bin to PATH, if it exists (bsc#1192248).
- Fixed get_kernel_version.c to work also for recent kernels on the s390/X platform (bsc#1191563).
- Support xz compressed kernel (bsc#1162581)");

  script_tag(name:"affected", value:"'aaa_base' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"aaa_base", rpm:"aaa_base~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-debuginfo", rpm:"aaa_base-debuginfo~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-debugsource", rpm:"aaa_base-debugsource~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-extras", rpm:"aaa_base-extras~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-malloccheck", rpm:"aaa_base-malloccheck~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"aaa_base", rpm:"aaa_base~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-debuginfo", rpm:"aaa_base-debuginfo~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-debugsource", rpm:"aaa_base-debugsource~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-extras", rpm:"aaa_base-extras~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-malloccheck", rpm:"aaa_base-malloccheck~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"aaa_base", rpm:"aaa_base~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-extras", rpm:"aaa_base-extras~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-malloccheck", rpm:"aaa_base-malloccheck~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"aaa_base", rpm:"aaa_base~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-extras", rpm:"aaa_base-extras~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aaa_base-malloccheck", rpm:"aaa_base-malloccheck~84.87+git20180409.04c9dae~3.52.1", rls:"SLES15.0SP1"))) {
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
