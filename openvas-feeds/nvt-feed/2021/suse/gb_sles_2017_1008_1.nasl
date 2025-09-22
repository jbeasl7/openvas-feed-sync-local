# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1008.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1008-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1008-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171008-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923349");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002800.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sblim-sfcb' package(s) announced via the SUSE-SU-2017:1008-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sblim-sfcb fixes the following issues:

Feature enhancements:
- A seperate sblim-sfcb-openssl1 package was added to the SECURITY Module.
 (fate#322032/bsc#1012814)

 This package can be installed additionaly, and the SysV Init script will
 pick the openssl1 variant on the next start, offering TLS 1.2 support
 on the WBEM SSL socket.

Bugfixes:
- Add sslNoSSLv3 and sslNoTLSv1 configuration options (bsc#923349, bsc#1008130)");

  script_tag(name:"affected", value:"'sblim-sfcb' package(s) on SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"sblim-sfcb-openssl1", rpm:"sblim-sfcb-openssl1~1.3.11~0.28.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"sblim-sfcb", rpm:"sblim-sfcb~1.3.11~0.28.1", rls:"SLES11.0SP4"))) {
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
