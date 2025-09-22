# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1333.1");
  script_cve_id("CVE-2024-51744", "CVE-2024-6104", "CVE-2025-22868", "CVE-2025-22869", "CVE-2025-22870", "CVE-2025-27144");
  script_tag(name:"creation_date", value:"2025-04-21 04:08:25 +0000 (Mon, 21 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-26 17:19:40 +0000 (Wed, 26 Jun 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1333-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251333-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239337");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/039052.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cosign' package(s) announced via the SUSE-SU-2025:1333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- fix: set tls config while retaining other fields from default http transport (#4007)
 - policy fuzzer: ignore known panics (#3993)
 - Fix for multiple WithRemote options (#3982)
 - Add nightly conformance test workflow (#3979)
 - Fix copy --only for signatures + update/align docs (#3904)");

  script_tag(name:"affected", value:"'cosign' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~2.5.0~150400.3.27.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~2.5.0~150400.3.27.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~2.5.0~150400.3.27.1", rls:"SLES15.0SP6"))) {
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
