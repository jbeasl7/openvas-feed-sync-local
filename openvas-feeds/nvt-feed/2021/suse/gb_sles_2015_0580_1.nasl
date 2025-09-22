# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0580.1");
  script_cve_id("CVE-2014-9114");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-05 11:45:58 +0000 (Wed, 05 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0580-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0580-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150580-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/761815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/859062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918041");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001313.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux' package(s) announced via the SUSE-SU-2015:0580-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for util-linux provides the following fixes:

 * Make blkid(8) issue only one READ on faulty devices. (bnc#859062)
 * Added option -r to fsck(8) to dump a few resource statistics after
 each successful run. (bnc#761815)
 * Prevent excessive clock drift calculations. (bnc#871698)
 * Check /etc/adjtime drift factor. (bnc#871698)
 * Prevent hang in exact hwclock adjustment. (bnc#871698)
 * Suppress warning that's not relevant on Linux systems. (bnc#871698)");

  script_tag(name:"affected", value:"'util-linux' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libblkid1", rpm:"libblkid1~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1-32bit", rpm:"libblkid1-32bit~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1-x86", rpm:"libblkid1-x86~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1", rpm:"libuuid1~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1-32bit", rpm:"libuuid1-32bit~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1-x86", rpm:"libuuid1-x86~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-lang", rpm:"util-linux-lang~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuid-runtime", rpm:"uuid-runtime~2.19.1~6.54.1", rls:"SLES11.0SP3"))) {
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
