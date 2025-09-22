# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2275.1");
  script_cve_id("CVE-2008-1483", "CVE-2016-10012", "CVE-2016-10708", "CVE-2017-15906");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-05 19:49:38 +0000 (Thu, 05 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2275-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2275-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182275-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076957");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-August/004398.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2018:2275-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh fixes the following issues:

Security issues fixed:

- CVE-2016-10012: Fix pre-auth compression checks that could be optimized away (bsc#1016370).
- CVE-2016-10708: Fix remote denial of service (NULL pointer dereference and daemon crash) via an out-of-sequence NEWKEYSmessage (bsc#1076957).
- CVE-2017-15906: Fix r/o sftp-server zero byte file creation (bsc#1065000).
- CVE-2008-1483: Fix accidental re-introduction of CVE-2008-1483 (bsc#1069509).

Bug fixes:

- bsc#1017099: Match conditions with uppercase hostnames fail (bsc#1017099)
- bsc#1053972: supportedKeyExchanges diffie-hellman-group1-sha1 is duplicated (bsc#1053972)
- bsc#1023275: Messages suppressed after upgrade from SLES 11 SP3 to SP4 (bsc#1023275)");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6p1~36.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.6p1~36.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-fips", rpm:"openssh-fips~6.6p1~36.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers", rpm:"openssh-helpers~6.6p1~36.3.1", rls:"SLES11.0SP4"))) {
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
