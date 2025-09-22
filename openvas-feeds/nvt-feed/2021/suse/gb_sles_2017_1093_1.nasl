# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1093.1");
  script_cve_id("CVE-2017-7392", "CVE-2017-7393", "CVE-2017-7394", "CVE-2017-7395", "CVE-2017-7396");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-04 17:55:18 +0000 (Tue, 04 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1093-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1093-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171093-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032880");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002824.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc' package(s) announced via the SUSE-SU-2017:1093-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tigervnc provides the several fixes.

These security issues were fixed:

- CVE-2017-7392, CVE-2017-7396: Client can cause leak in VNC server (bsc#1031886)
- CVE-2017-7395: Authenticated VNC client can crash VNC server (bsc#1031877)
- CVE-2017-7394: Client can crash or block VNC server (bsc#1031879)
- CVE-2017-7393: Authenticated client can cause double free in VNC server (bsc#1031875)
- Prevent buffer overflow in VNC client, allowing for crashing the client (bnc#1032880)");

  script_tag(name:"affected", value:"'tigervnc' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.4.3~24.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~1.4.3~24.1", rls:"SLES12.0SP1"))) {
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
