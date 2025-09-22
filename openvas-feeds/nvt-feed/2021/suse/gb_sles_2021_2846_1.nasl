# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2846.1");
  script_cve_id("CVE-2020-0429", "CVE-2021-28688", "CVE-2021-37576");
  script_tag(name:"creation_date", value:"2021-08-26 02:26:42 +0000 (Thu, 26 Aug 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-05 18:09:19 +0000 (Thu, 05 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2846-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2846-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212846-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188842");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-August/009359.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 40 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2021:2846-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.180-94_147 fixes several issues.

The following security issues were fixed:

- CVE-2021-37576: On the powerpc platform KVM guest OS users could cause host OS memory corruption via rtas_args.nargs (bsc#1188838).
- CVE-2021-28688: The fix for XSA-365 includes initialization of pointers such that subsequent cleanup code wouldn't use uninitialized or stale values. This initialization went too far and may under certain conditions also overwrite pointers which are in need of cleaning up. (bsc#1183646)
- CVE-2020-0429: Fixed a potential local privilege escalation in l2tp_session_delete and related functions of l2tp_core.c (bsc#1176724).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 40 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_147-default", rpm:"kgraft-patch-4_4_180-94_147-default~2~2.1", rls:"SLES12.0SP3"))) {
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
