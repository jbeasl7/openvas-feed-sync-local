# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3480.1");
  script_cve_id("CVE-2020-10696", "CVE-2021-20206", "CVE-2022-27651");
  script_tag(name:"creation_date", value:"2022-10-03 04:37:04 +0000 (Mon, 03 Oct 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-01 13:18:14 +0000 (Wed, 01 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3480-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223480-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197870");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-September/012462.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah' package(s) announced via the SUSE-SU-2022:3480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

- Updated to version 1.26.0:
 - CVE-2022-27651: Fixed an issue where containers were incorrectly started with non-empty inheritable Linux process capabilities (bsc#1197870).
 - CVE-2021-20206: Fixed an issue in libcni that could allow an attacker to execute arbitrary binaries on the host (bsc#1181961).
 - CVE-2020-10696: Fixed an issue that could lead to files being overwritten during the image building process (bsc#1167864).");

  script_tag(name:"affected", value:"'buildah' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.25.1~150100.3.13.12", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.25.1~150100.3.13.12", rls:"SLES15.0SP2"))) {
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
