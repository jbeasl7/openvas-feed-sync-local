# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0180");
  script_cve_id("CVE-2022-21698");
  script_tag(name:"creation_date", value:"2022-05-19 07:28:20 +0000 (Thu, 19 May 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-24 02:59:10 +0000 (Thu, 24 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0180)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0180");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0180.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30054");
  script_xref(name:"URL", value:"https://github.com/prometheus/client_golang/security/advisories/GHSA-cg3q-j54f-5p7p");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/FY3N7H6VSDZM37B4SKM2PFFCUWU7QYWN/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DCH7WCUVWWLVX6ITJIZWAVCPF7EKZ2D6/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-client' package(s) announced via the MGASA-2022-0180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HTTP server is susceptible to a Denial of Service through unbounded
cardinality, and potential memory exhaustion, when handling requests with
non-standard HTTP methods.");

  script_tag(name:"affected", value:"'golang-github-prometheus-client' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-client", rpm:"golang-github-prometheus-client~1.11.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-client-devel", rpm:"golang-github-prometheus-client-devel~1.11.1~1.mga8", rls:"MAGEIA8"))) {
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
