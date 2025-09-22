# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3189.1");
  script_cve_id("CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948", "CVE-2016-7951", "CVE-2016-7952", "CVE-2016-7953");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 02:51:29 +0000 (Thu, 15 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3189-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3189-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163189-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003023");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-December/002495.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-libs' package(s) announced via the SUSE-SU-2016:3189-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-libs fixes the following issues:

 - insufficient validation of data from the X server can cause a
 one byte buffer read underrun (bsc#1003023, CVE-2016-7953)
 - insufficient validation of data from the X server can cause out
 of boundary memory access or endless loops (Denial of Service)
 (bsc#1003012, CVE-2016-7951, CVE-2016-7952)
 - insufficient validation of data from the X server can cause out
 of boundary memory writes (bsc#1003000, CVE-2016-7947, CVE-2016-7948)
 - insufficient validation of data from the X server can cause out
 of boundary memory access or endless loops (Denial of Service).
 (bsc#1002998, CVE-2016-7945, CVE-2016-7946)");

  script_tag(name:"affected", value:"'xorg-x11-libs' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs-32bit", rpm:"xorg-x11-libs-32bit~7.4~8.26.49.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~7.4~8.26.49.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs-x86", rpm:"xorg-x11-libs-x86~7.4~8.26.49.1", rls:"SLES11.0SP4"))) {
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
