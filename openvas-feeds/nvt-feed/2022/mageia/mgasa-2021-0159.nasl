# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0159");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2021-0159)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0159");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0159.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28320");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/A73URKLEFEB5USSGSLKTP7XWE5JUKSB7/");
  script_xref(name:"URL", value:"https://lists.zeromq.org/pipermail/zeromq-announce/2021-January/000068.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cppzmq, zeromq' package(s) announced via the MGASA-2021-0159 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Memory leak in client induced by malicious server without CURVE/ZAP
(rhbz#1921972).

Stack overflow on server running PUB/XPUB socket (rhbz#1921976).

Heap overflow when receiving malformed ZMTP v1 packets (rhbz#1921983).

Memory leaks via metadata messages processed by PUB sockets (rhbz#1921989).

Also, the cppzmq package has been rebuilt to fix the broken dependency on
zeromq-devel.");

  script_tag(name:"affected", value:"'cppzmq, zeromq' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"cppzmq", rpm:"cppzmq~4.3.0~2.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cppzmq-devel", rpm:"lib64cppzmq-devel~4.3.0~2.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zmq-devel", rpm:"lib64zmq-devel~4.3.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zmq5", rpm:"lib64zmq5~4.3.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcppzmq-devel", rpm:"libcppzmq-devel~4.3.0~2.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq-devel", rpm:"libzmq-devel~4.3.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5", rpm:"libzmq5~4.3.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq", rpm:"zeromq~4.3.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq-utils", rpm:"zeromq-utils~4.3.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"cppzmq", rpm:"cppzmq~4.7.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cppzmq-devel", rpm:"lib64cppzmq-devel~4.7.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zmq-devel", rpm:"lib64zmq-devel~4.3.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zmq5", rpm:"lib64zmq5~4.3.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcppzmq-devel", rpm:"libcppzmq-devel~4.7.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq-devel", rpm:"libzmq-devel~4.3.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5", rpm:"libzmq5~4.3.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq", rpm:"zeromq~4.3.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq-utils", rpm:"zeromq-utils~4.3.4~1.1.mga8", rls:"MAGEIA8"))) {
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
