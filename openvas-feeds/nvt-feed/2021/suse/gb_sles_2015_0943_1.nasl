# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0943.1");
  script_cve_id("CVE-2012-2652", "CVE-2012-3515", "CVE-2013-2007", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0943-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0943-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150943-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/709405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/712137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/722643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/722958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/724813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/725008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/747339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/753313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/757031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/764526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/770153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/772586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/777084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/786813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/818182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929339");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-May/001407.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'KVM' package(s) announced via the SUSE-SU-2015:0943-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a file permission issue with qga (the QEMU Guest Agent)
from the qemu/kvm package and includes several bug-fixes.

(bnc#818182) (CVE-2013-2007) (bnc#786813) (bnc#725008) (bnc#712137)
(bnc#824340)

Security Issues:

 * CVE-2013-2007
 <[link moved to references]>");

  script_tag(name:"affected", value:"'KVM' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server for SAP Applications 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~0.15.1~0.27.1", rls:"SLES11.0SP2"))) {
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
