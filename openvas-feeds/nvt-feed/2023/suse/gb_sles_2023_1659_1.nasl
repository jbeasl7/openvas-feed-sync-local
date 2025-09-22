# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1659.1");
  script_cve_id("CVE-2023-28486", "CVE-2023-28487");
  script_tag(name:"creation_date", value:"2023-03-30 04:21:53 +0000 (Thu, 30 Mar 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-22 15:01:17 +0000 (Wed, 22 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1659-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1659-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231659-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209362");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-March/028461.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the SUSE-SU-2023:1659-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2023-28486: Fixed missing control characters escaping in log messages (bsc#1209362).
- CVE-2023-28487: Fixed missing control characters escaping in sudoreplay output (bsc#1209361).

Other fixes:

- Fix a situation where 'sudo -U otheruser -l' would dereference a NULL pointer (bsc#1206483).
- Do not re-enable the reader when flushing the buffers as part of pty_finish() (bsc#1203201).");

  script_tag(name:"affected", value:"'sudo' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.27~4.38.1", rls:"SLES12.0SP5"))) {
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
