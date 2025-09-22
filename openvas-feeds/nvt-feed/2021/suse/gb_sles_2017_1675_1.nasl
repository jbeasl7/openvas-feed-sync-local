# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1675.1");
  script_cve_id("CVE-2017-2624");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-02 20:22:03 +0000 (Tue, 02 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1675-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1675-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171675-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039042");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002980.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2017:1675-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-server provides the following fixes:

- Remove unused function with use-after-free issue. (bsc#1025035)
- Use arc4random to generate cookies. (bsc#1025084)
- Prevent timing attack against MIT cookie. (bsc#1025029, CVE-2017-2624)
- XDrawArc performance improvement. (bsc#1019649)
- Re-enable indirect GLX by default. (bsc#1039042)
- Add IndirectGLX ServerFlags option which allows users to enable or disable indirect GLX. (bsc#1032509)
- Fix dashing in GLAMOR. (bsc#1021803)
- Fix X server crash on drawing dashed lines. (bsc#1025985)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.6_1.18.3~71.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.6_1.18.3~71.1", rls:"SLES12.0SP2"))) {
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
