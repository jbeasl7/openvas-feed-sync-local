# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2116.1");
  script_cve_id("CVE-2020-14344");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 20:26:16 +0000 (Thu, 06 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2116-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2116-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202116-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174628");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-August/007217.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libX11' package(s) announced via the SUSE-SU-2020:2116-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libX11 fixes the following issues:

- Fixed XIM client heap overflows (CVE-2020-14344, bsc#1174628)");

  script_tag(name:"affected", value:"'libX11' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~3.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0", rpm:"libxcb-composite0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0-debuginfo", rpm:"libxcb-composite0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0", rpm:"libxcb-damage0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0-debuginfo", rpm:"libxcb-damage0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-debugsource", rpm:"libxcb-debugsource~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel", rpm:"libxcb-devel~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel-doc", rpm:"libxcb-devel-doc~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0", rpm:"libxcb-dpms0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0-debuginfo", rpm:"libxcb-dpms0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0", rpm:"libxcb-dri2-0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-32bit", rpm:"libxcb-dri2-0-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-32bit-debuginfo", rpm:"libxcb-dri2-0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-debuginfo", rpm:"libxcb-dri2-0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0", rpm:"libxcb-dri3-0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-32bit", rpm:"libxcb-dri3-0-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-32bit-debuginfo", rpm:"libxcb-dri3-0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-debuginfo", rpm:"libxcb-dri3-0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0", rpm:"libxcb-glx0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-32bit", rpm:"libxcb-glx0-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-32bit-debuginfo", rpm:"libxcb-glx0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-debuginfo", rpm:"libxcb-glx0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0", rpm:"libxcb-present0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-32bit", rpm:"libxcb-present0-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-32bit-debuginfo", rpm:"libxcb-present0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-debuginfo", rpm:"libxcb-present0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0", rpm:"libxcb-randr0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0-debuginfo", rpm:"libxcb-randr0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0", rpm:"libxcb-record0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0-debuginfo", rpm:"libxcb-record0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0", rpm:"libxcb-render0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-debuginfo", rpm:"libxcb-render0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0", rpm:"libxcb-res0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0-debuginfo", rpm:"libxcb-res0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0", rpm:"libxcb-screensaver0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0-debuginfo", rpm:"libxcb-screensaver0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0", rpm:"libxcb-shape0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0-debuginfo", rpm:"libxcb-shape0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0", rpm:"libxcb-shm0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-debuginfo", rpm:"libxcb-shm0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1", rpm:"libxcb-sync1~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-32bit", rpm:"libxcb-sync1-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-32bit-debuginfo", rpm:"libxcb-sync1-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-debuginfo", rpm:"libxcb-sync1-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0", rpm:"libxcb-xf86dri0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0-debuginfo", rpm:"libxcb-xf86dri0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0", rpm:"libxcb-xfixes0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-32bit", rpm:"libxcb-xfixes0-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-32bit-debuginfo", rpm:"libxcb-xfixes0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-debuginfo", rpm:"libxcb-xfixes0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0", rpm:"libxcb-xinerama0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0-debuginfo", rpm:"libxcb-xinerama0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0", rpm:"libxcb-xinput0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0-debuginfo", rpm:"libxcb-xinput0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1", rpm:"libxcb-xkb1~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1-debuginfo", rpm:"libxcb-xkb1-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0", rpm:"libxcb-xtest0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0-debuginfo", rpm:"libxcb-xtest0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0", rpm:"libxcb-xv0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0-debuginfo", rpm:"libxcb-xv0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0", rpm:"libxcb-xvmc0~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0-debuginfo", rpm:"libxcb-xvmc0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1", rpm:"libxcb1~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-32bit", rpm:"libxcb1-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-32bit-debuginfo", rpm:"libxcb1-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-debuginfo", rpm:"libxcb1-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-32bit", rpm:"libxcb-render0-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-32bit-debuginfo", rpm:"libxcb-render0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-32bit", rpm:"libxcb-shm0-32bit~1.13~3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-32bit-debuginfo", rpm:"libxcb-shm0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~3.6.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0", rpm:"libxcb-composite0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0-debuginfo", rpm:"libxcb-composite0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0", rpm:"libxcb-damage0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0-debuginfo", rpm:"libxcb-damage0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-debugsource", rpm:"libxcb-debugsource~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel", rpm:"libxcb-devel~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel-doc", rpm:"libxcb-devel-doc~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0", rpm:"libxcb-dpms0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0-debuginfo", rpm:"libxcb-dpms0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0", rpm:"libxcb-dri2-0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-32bit", rpm:"libxcb-dri2-0-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-32bit-debuginfo", rpm:"libxcb-dri2-0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-debuginfo", rpm:"libxcb-dri2-0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0", rpm:"libxcb-dri3-0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-32bit", rpm:"libxcb-dri3-0-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-32bit-debuginfo", rpm:"libxcb-dri3-0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-debuginfo", rpm:"libxcb-dri3-0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0", rpm:"libxcb-glx0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-32bit", rpm:"libxcb-glx0-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-32bit-debuginfo", rpm:"libxcb-glx0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-debuginfo", rpm:"libxcb-glx0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0", rpm:"libxcb-present0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-32bit", rpm:"libxcb-present0-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-32bit-debuginfo", rpm:"libxcb-present0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-debuginfo", rpm:"libxcb-present0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0", rpm:"libxcb-randr0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0-debuginfo", rpm:"libxcb-randr0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0", rpm:"libxcb-record0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0-debuginfo", rpm:"libxcb-record0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0", rpm:"libxcb-render0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-debuginfo", rpm:"libxcb-render0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0", rpm:"libxcb-res0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0-debuginfo", rpm:"libxcb-res0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0", rpm:"libxcb-screensaver0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0-debuginfo", rpm:"libxcb-screensaver0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0", rpm:"libxcb-shape0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0-debuginfo", rpm:"libxcb-shape0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0", rpm:"libxcb-shm0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-debuginfo", rpm:"libxcb-shm0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1", rpm:"libxcb-sync1~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-32bit", rpm:"libxcb-sync1-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-32bit-debuginfo", rpm:"libxcb-sync1-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-debuginfo", rpm:"libxcb-sync1-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0", rpm:"libxcb-xf86dri0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0-debuginfo", rpm:"libxcb-xf86dri0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0", rpm:"libxcb-xfixes0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-32bit", rpm:"libxcb-xfixes0-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-32bit-debuginfo", rpm:"libxcb-xfixes0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-debuginfo", rpm:"libxcb-xfixes0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0", rpm:"libxcb-xinerama0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0-debuginfo", rpm:"libxcb-xinerama0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0", rpm:"libxcb-xinput0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0-debuginfo", rpm:"libxcb-xinput0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1", rpm:"libxcb-xkb1~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1-debuginfo", rpm:"libxcb-xkb1-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0", rpm:"libxcb-xtest0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0-debuginfo", rpm:"libxcb-xtest0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0", rpm:"libxcb-xv0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0-debuginfo", rpm:"libxcb-xv0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0", rpm:"libxcb-xvmc0~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0-debuginfo", rpm:"libxcb-xvmc0-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1", rpm:"libxcb1~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-32bit", rpm:"libxcb1-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-32bit-debuginfo", rpm:"libxcb1-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-debuginfo", rpm:"libxcb1-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-32bit", rpm:"libxcb-render0-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0-32bit-debuginfo", rpm:"libxcb-render0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-32bit", rpm:"libxcb-shm0-32bit~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0-32bit-debuginfo", rpm:"libxcb-shm0-32bit-debuginfo~1.13~3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~3.6.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~3.6.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~3.6.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~3.6.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~3.6.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~3.6.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-composite0", rpm:"libxcb-composite0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-damage0", rpm:"libxcb-damage0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel", rpm:"libxcb-devel~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-devel-doc", rpm:"libxcb-devel-doc~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dpms0", rpm:"libxcb-dpms0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0", rpm:"libxcb-dri2-0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri2-0-32bit", rpm:"libxcb-dri2-0-32bit~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0", rpm:"libxcb-dri3-0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-dri3-0-32bit", rpm:"libxcb-dri3-0-32bit~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0", rpm:"libxcb-glx0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-glx0-32bit", rpm:"libxcb-glx0-32bit~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0", rpm:"libxcb-present0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-present0-32bit", rpm:"libxcb-present0-32bit~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-randr0", rpm:"libxcb-randr0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-record0", rpm:"libxcb-record0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-render0", rpm:"libxcb-render0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-res0", rpm:"libxcb-res0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-screensaver0", rpm:"libxcb-screensaver0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shape0", rpm:"libxcb-shape0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-shm0", rpm:"libxcb-shm0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1", rpm:"libxcb-sync1~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-sync1-32bit", rpm:"libxcb-sync1-32bit~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xf86dri0", rpm:"libxcb-xf86dri0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0", rpm:"libxcb-xfixes0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xfixes0-32bit", rpm:"libxcb-xfixes0-32bit~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinerama0", rpm:"libxcb-xinerama0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xinput0", rpm:"libxcb-xinput0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xkb1", rpm:"libxcb-xkb1~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xtest0", rpm:"libxcb-xtest0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xv0", rpm:"libxcb-xv0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb-xvmc0", rpm:"libxcb-xvmc0~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1", rpm:"libxcb1~1.13~3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxcb1-32bit", rpm:"libxcb1-32bit~1.13~3.5.1", rls:"SLES15.0"))) {
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
