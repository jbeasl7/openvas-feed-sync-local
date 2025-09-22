# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2864.1");
  script_cve_id("CVE-2018-10902", "CVE-2018-10938", "CVE-2018-5390");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-01 16:41:56 +0000 (Thu, 01 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2864-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2864-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182864-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106191");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004602.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 23 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2018:2864-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.121-92_85 fixes several issues.

The following security issues were fixed:

- CVE-2018-5390: Prevent very expensive calls to tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() for every incoming TCP packet which can lead to a denial of service (bsc#1102682).
- CVE-2018-10938: Fixed an infinite loop in the cipso_v4_optptr() function leading to a denial-of-service via crafted network packets (bsc#1106191).
- CVE-2018-10902: It was found that the raw midi kernel driver did not protect against concurrent access which lead to a double realloc (double free) in snd_rawmidi_input_params() and snd_rawmidi_output_status(), allowing a malicious local attacker to use this for privilege escalation (bsc#1105323).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 23 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_120-92_70-default", rpm:"kgraft-patch-4_4_120-92_70-default~6~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_73-default", rpm:"kgraft-patch-4_4_121-92_73-default~5~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_80-default", rpm:"kgraft-patch-4_4_121-92_80-default~5~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_85-default", rpm:"kgraft-patch-4_4_121-92_85-default~3~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_92-default", rpm:"kgraft-patch-4_4_121-92_92-default~3~2.1", rls:"SLES12.0SP2"))) {
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
