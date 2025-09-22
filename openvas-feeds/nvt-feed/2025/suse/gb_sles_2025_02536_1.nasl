# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02536.1");
  script_cve_id("CVE-2016-9840");
  script_tag(name:"creation_date", value:"2025-07-30 04:22:58 +0000 (Wed, 30 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-30 18:59:52 +0000 (Tue, 30 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02536-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02536-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502536-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245936");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040943.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'boost' package(s) announced via the SUSE-SU-2025:02536-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for boost fixes the following issues:

- CVE-2016-9840: Fixed out-of-bounds pointer arithmetic in zlib in beast (bsc#1245936)");

  script_tag(name:"affected", value:"'boost' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"boost-license1_66_0", rpm:"boost-license1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_66_0", rpm:"libboost_atomic1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_66_0-devel", rpm:"libboost_atomic1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1_66_0", rpm:"libboost_chrono1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1_66_0-devel", rpm:"libboost_chrono1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1_66_0", rpm:"libboost_container1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1_66_0-devel", rpm:"libboost_container1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1_66_0", rpm:"libboost_context1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1_66_0-devel", rpm:"libboost_context1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1_66_0", rpm:"libboost_coroutine1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1_66_0-devel", rpm:"libboost_coroutine1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_66_0", rpm:"libboost_date_time1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_66_0-devel", rpm:"libboost_date_time1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_fiber1_66_0", rpm:"libboost_fiber1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_fiber1_66_0-devel", rpm:"libboost_fiber1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1_66_0", rpm:"libboost_filesystem1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1_66_0-devel", rpm:"libboost_filesystem1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1_66_0", rpm:"libboost_graph1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1_66_0-devel", rpm:"libboost_graph1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_headers1_66_0-devel", rpm:"libboost_headers1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_66_0", rpm:"libboost_iostreams1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_66_0-devel", rpm:"libboost_iostreams1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1_66_0", rpm:"libboost_locale1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1_66_0-devel", rpm:"libboost_locale1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1_66_0", rpm:"libboost_log1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1_66_0-devel", rpm:"libboost_log1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1_66_0", rpm:"libboost_math1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1_66_0-devel", rpm:"libboost_math1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_mpi1_66_0", rpm:"libboost_mpi1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_mpi1_66_0-devel", rpm:"libboost_mpi1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_mpi_python-py2_7-1_66_0", rpm:"libboost_mpi_python-py2_7-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_mpi_python-py2_7-1_66_0-devel", rpm:"libboost_mpi_python-py2_7-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_numpy-py3-1_66_0", rpm:"libboost_numpy-py3-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_numpy-py3-1_66_0-devel", rpm:"libboost_numpy-py3-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_66_0", rpm:"libboost_program_options1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_66_0-devel", rpm:"libboost_program_options1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py2_7-1_66_0", rpm:"libboost_python-py2_7-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py2_7-1_66_0-devel", rpm:"libboost_python-py2_7-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py3-1_66_0", rpm:"libboost_python-py3-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py3-1_66_0-devel", rpm:"libboost_python-py3-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_66_0", rpm:"libboost_random1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_66_0-devel", rpm:"libboost_random1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_66_0", rpm:"libboost_regex1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_66_0-devel", rpm:"libboost_regex1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1_66_0", rpm:"libboost_serialization1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1_66_0-devel", rpm:"libboost_serialization1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_66_0", rpm:"libboost_signals1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_66_0-devel", rpm:"libboost_signals1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_stacktrace1_66_0", rpm:"libboost_stacktrace1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_stacktrace1_66_0-devel", rpm:"libboost_stacktrace1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_66_0", rpm:"libboost_system1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_66_0-devel", rpm:"libboost_system1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_test1_66_0", rpm:"libboost_test1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_test1_66_0-devel", rpm:"libboost_test1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_66_0", rpm:"libboost_thread1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_66_0-devel", rpm:"libboost_thread1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1_66_0", rpm:"libboost_timer1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1_66_0-devel", rpm:"libboost_timer1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1_66_0", rpm:"libboost_type_erasure1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1_66_0-devel", rpm:"libboost_type_erasure1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1_66_0", rpm:"libboost_wave1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1_66_0-devel", rpm:"libboost_wave1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"boost-license1_66_0", rpm:"boost-license1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_66_0", rpm:"libboost_atomic1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_66_0-devel", rpm:"libboost_atomic1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1_66_0", rpm:"libboost_chrono1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1_66_0-devel", rpm:"libboost_chrono1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1_66_0", rpm:"libboost_container1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1_66_0-devel", rpm:"libboost_container1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1_66_0", rpm:"libboost_context1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1_66_0-devel", rpm:"libboost_context1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1_66_0", rpm:"libboost_coroutine1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1_66_0-devel", rpm:"libboost_coroutine1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_66_0", rpm:"libboost_date_time1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_66_0-devel", rpm:"libboost_date_time1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_fiber1_66_0", rpm:"libboost_fiber1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_fiber1_66_0-devel", rpm:"libboost_fiber1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1_66_0", rpm:"libboost_filesystem1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1_66_0-devel", rpm:"libboost_filesystem1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1_66_0", rpm:"libboost_graph1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1_66_0-devel", rpm:"libboost_graph1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_headers1_66_0-devel", rpm:"libboost_headers1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_66_0", rpm:"libboost_iostreams1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_66_0-devel", rpm:"libboost_iostreams1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1_66_0", rpm:"libboost_locale1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1_66_0-devel", rpm:"libboost_locale1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1_66_0", rpm:"libboost_log1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1_66_0-devel", rpm:"libboost_log1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1_66_0", rpm:"libboost_math1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1_66_0-devel", rpm:"libboost_math1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_numpy-py3-1_66_0", rpm:"libboost_numpy-py3-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_numpy-py3-1_66_0-devel", rpm:"libboost_numpy-py3-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_66_0", rpm:"libboost_program_options1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_66_0-devel", rpm:"libboost_program_options1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py3-1_66_0", rpm:"libboost_python-py3-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py3-1_66_0-devel", rpm:"libboost_python-py3-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_66_0", rpm:"libboost_random1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_66_0-devel", rpm:"libboost_random1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_66_0", rpm:"libboost_regex1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_66_0-devel", rpm:"libboost_regex1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1_66_0", rpm:"libboost_serialization1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1_66_0-devel", rpm:"libboost_serialization1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_66_0", rpm:"libboost_signals1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_66_0-devel", rpm:"libboost_signals1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_stacktrace1_66_0", rpm:"libboost_stacktrace1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_stacktrace1_66_0-devel", rpm:"libboost_stacktrace1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_66_0", rpm:"libboost_system1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_66_0-devel", rpm:"libboost_system1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_test1_66_0", rpm:"libboost_test1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_test1_66_0-devel", rpm:"libboost_test1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_66_0", rpm:"libboost_thread1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_66_0-devel", rpm:"libboost_thread1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1_66_0", rpm:"libboost_timer1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1_66_0-devel", rpm:"libboost_timer1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1_66_0", rpm:"libboost_type_erasure1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1_66_0-devel", rpm:"libboost_type_erasure1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1_66_0", rpm:"libboost_wave1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1_66_0-devel", rpm:"libboost_wave1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"boost-license1_66_0", rpm:"boost-license1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_66_0", rpm:"libboost_atomic1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_66_0-devel", rpm:"libboost_atomic1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1_66_0", rpm:"libboost_chrono1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1_66_0-devel", rpm:"libboost_chrono1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1_66_0", rpm:"libboost_container1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1_66_0-devel", rpm:"libboost_container1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1_66_0", rpm:"libboost_context1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1_66_0-devel", rpm:"libboost_context1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1_66_0", rpm:"libboost_coroutine1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1_66_0-devel", rpm:"libboost_coroutine1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_66_0", rpm:"libboost_date_time1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_66_0-devel", rpm:"libboost_date_time1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_fiber1_66_0", rpm:"libboost_fiber1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_fiber1_66_0-devel", rpm:"libboost_fiber1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1_66_0", rpm:"libboost_filesystem1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1_66_0-devel", rpm:"libboost_filesystem1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1_66_0", rpm:"libboost_graph1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1_66_0-devel", rpm:"libboost_graph1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_headers1_66_0-devel", rpm:"libboost_headers1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_66_0", rpm:"libboost_iostreams1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_66_0-devel", rpm:"libboost_iostreams1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1_66_0", rpm:"libboost_locale1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1_66_0-devel", rpm:"libboost_locale1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1_66_0", rpm:"libboost_log1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1_66_0-devel", rpm:"libboost_log1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1_66_0", rpm:"libboost_math1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1_66_0-devel", rpm:"libboost_math1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_numpy-py3-1_66_0", rpm:"libboost_numpy-py3-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_numpy-py3-1_66_0-devel", rpm:"libboost_numpy-py3-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_66_0", rpm:"libboost_program_options1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_66_0-devel", rpm:"libboost_program_options1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py3-1_66_0", rpm:"libboost_python-py3-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py3-1_66_0-devel", rpm:"libboost_python-py3-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_66_0", rpm:"libboost_random1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_66_0-devel", rpm:"libboost_random1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_66_0", rpm:"libboost_regex1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_66_0-devel", rpm:"libboost_regex1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1_66_0", rpm:"libboost_serialization1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1_66_0-devel", rpm:"libboost_serialization1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_66_0", rpm:"libboost_signals1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_66_0-devel", rpm:"libboost_signals1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_stacktrace1_66_0", rpm:"libboost_stacktrace1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_stacktrace1_66_0-devel", rpm:"libboost_stacktrace1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_66_0", rpm:"libboost_system1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_66_0-devel", rpm:"libboost_system1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_test1_66_0", rpm:"libboost_test1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_test1_66_0-devel", rpm:"libboost_test1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_66_0", rpm:"libboost_thread1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_66_0-devel", rpm:"libboost_thread1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1_66_0", rpm:"libboost_timer1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1_66_0-devel", rpm:"libboost_timer1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1_66_0", rpm:"libboost_type_erasure1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1_66_0-devel", rpm:"libboost_type_erasure1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1_66_0", rpm:"libboost_wave1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1_66_0-devel", rpm:"libboost_wave1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"boost-license1_66_0", rpm:"boost-license1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_66_0", rpm:"libboost_atomic1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1_66_0-devel", rpm:"libboost_atomic1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1_66_0", rpm:"libboost_chrono1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1_66_0-devel", rpm:"libboost_chrono1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1_66_0", rpm:"libboost_container1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1_66_0-devel", rpm:"libboost_container1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1_66_0", rpm:"libboost_context1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1_66_0-devel", rpm:"libboost_context1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1_66_0", rpm:"libboost_coroutine1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1_66_0-devel", rpm:"libboost_coroutine1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_66_0", rpm:"libboost_date_time1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1_66_0-devel", rpm:"libboost_date_time1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_fiber1_66_0", rpm:"libboost_fiber1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_fiber1_66_0-devel", rpm:"libboost_fiber1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1_66_0", rpm:"libboost_filesystem1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1_66_0-devel", rpm:"libboost_filesystem1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1_66_0", rpm:"libboost_graph1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1_66_0-devel", rpm:"libboost_graph1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_headers1_66_0-devel", rpm:"libboost_headers1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_66_0", rpm:"libboost_iostreams1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1_66_0-devel", rpm:"libboost_iostreams1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1_66_0", rpm:"libboost_locale1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1_66_0-devel", rpm:"libboost_locale1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1_66_0", rpm:"libboost_log1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1_66_0-devel", rpm:"libboost_log1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1_66_0", rpm:"libboost_math1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1_66_0-devel", rpm:"libboost_math1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_66_0", rpm:"libboost_program_options1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_66_0-devel", rpm:"libboost_program_options1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py3-1_66_0", rpm:"libboost_python-py3-1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python-py3-1_66_0-devel", rpm:"libboost_python-py3-1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_66_0", rpm:"libboost_random1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1_66_0-devel", rpm:"libboost_random1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_66_0", rpm:"libboost_regex1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_66_0-devel", rpm:"libboost_regex1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1_66_0", rpm:"libboost_serialization1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1_66_0-devel", rpm:"libboost_serialization1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_66_0", rpm:"libboost_signals1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_66_0-devel", rpm:"libboost_signals1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_stacktrace1_66_0", rpm:"libboost_stacktrace1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_stacktrace1_66_0-devel", rpm:"libboost_stacktrace1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_66_0", rpm:"libboost_system1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1_66_0-devel", rpm:"libboost_system1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_test1_66_0", rpm:"libboost_test1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_test1_66_0-devel", rpm:"libboost_test1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_66_0", rpm:"libboost_thread1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1_66_0-devel", rpm:"libboost_thread1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1_66_0", rpm:"libboost_timer1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1_66_0-devel", rpm:"libboost_timer1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1_66_0", rpm:"libboost_type_erasure1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1_66_0-devel", rpm:"libboost_type_erasure1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1_66_0", rpm:"libboost_wave1_66_0~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1_66_0-devel", rpm:"libboost_wave1_66_0-devel~1.66.0~150200.12.7.1", rls:"SLES15.0SP6"))) {
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
