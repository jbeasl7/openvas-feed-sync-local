# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0931.1");
  script_cve_id("CVE-2015-5313");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 15:20:09 +0000 (Mon, 18 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0931-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0931-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160931-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961173");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-April/001977.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2016:0931-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvirt fixes the following issues:

Security issue:
- CVE-2015-5313: directory directory traversal privilege
 escalation vulnerability. (bsc#953110)

Bugs fixed:
- bsc#960305: xenxs: support parsing and formatting vif bandwidth
- bsc#961173: xen: use correct domctl version in domaininfolist union
- bsc#959094: xen: Disable building xen-inotify subdriver. It is unmaintained
 and contains bugs that can cause client connection failures.
- bsc#948686: qemu: Use PAUSED state for domains that are starting up
- bsc#948516: Fix profile_status to distringuish between errors and unconfined
 domains.");

  script_tag(name:"affected", value:"'libvirt' package(s) on SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.2.5~12.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.2.5~12.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-32bit", rpm:"libvirt-client-32bit~1.2.5~12.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~1.2.5~12.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~1.2.5~12.3", rls:"SLES11.0SP4"))) {
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
