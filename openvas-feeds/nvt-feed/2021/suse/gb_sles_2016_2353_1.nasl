# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2353.1");
  script_cve_id("CVE-2016-5746");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-27 16:31:10 +0000 (Tue, 27 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2353-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2353-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162353-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996208");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-September/002284.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yast2-storage' package(s) announced via the SUSE-SU-2016:2353-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for yast2-storage provides the following fixes:

Security issues fixed:
- Use standard IPC, and not temporary files, to pass passwords between processes.
 (bsc#986971, CVE-2016-5746)

Non security bugs fixed:
- Fix usage of complete multipath disk as LVM physical volume. (bsc#984245)
- Load the correct multipath module (dm-multipath). (bsc#937942)
- Improve message for creating volumes with a filesystem but without a mount point.
 (bsc#996208)");

  script_tag(name:"affected", value:"'yast2-storage' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"yast2-storage", rpm:"yast2-storage~2.17.161~5.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-storage-lib", rpm:"yast2-storage-lib~2.17.161~5.1", rls:"SLES11.0SP4"))) {
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
