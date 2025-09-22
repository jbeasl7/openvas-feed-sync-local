# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893226");
  script_cve_id("CVE-2020-28601", "CVE-2020-28602", "CVE-2020-28603", "CVE-2020-28604", "CVE-2020-28605", "CVE-2020-28606", "CVE-2020-28607", "CVE-2020-28608", "CVE-2020-28609", "CVE-2020-28610", "CVE-2020-28611", "CVE-2020-28612", "CVE-2020-28613", "CVE-2020-28614", "CVE-2020-28615", "CVE-2020-28616", "CVE-2020-28617", "CVE-2020-28618", "CVE-2020-28619", "CVE-2020-28620", "CVE-2020-28621", "CVE-2020-28622", "CVE-2020-28623", "CVE-2020-28624", "CVE-2020-28625", "CVE-2020-28626", "CVE-2020-28627", "CVE-2020-28628", "CVE-2020-28629", "CVE-2020-28630", "CVE-2020-28631", "CVE-2020-28632", "CVE-2020-28633", "CVE-2020-28634", "CVE-2020-28635", "CVE-2020-28636", "CVE-2020-35628", "CVE-2020-35629", "CVE-2020-35630", "CVE-2020-35631", "CVE-2020-35632", "CVE-2020-35633", "CVE-2020-35634", "CVE-2020-35635", "CVE-2020-35636");
  script_tag(name:"creation_date", value:"2022-12-07 02:00:49 +0000 (Wed, 07 Dec 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-10 17:49:24 +0000 (Wed, 10 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-3226-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3226-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3226-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cgal");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cgal' package(s) announced via the DLA-3226-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When parsing files containing Nef polygon data, several memory access violations may happen. Many of these allow code execution.

CVE-2020-28601

A code execution vulnerability exists in the Nef polygon-parsing functionality of CGAL. An oob read vulnerability exists in Nef_2/PM_io_parser.h PM_io_parser::read_vertex() Face_of[] OOB read. An attacker can provide malicious input to trigger this vulnerability.

CVE-2020-28602

Multiple code execution vulnerabilities exist in the Nef polygon parsing functionality of CGAL. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which could lead to code execution. An attacker can provide malicious input to trigger any of these vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h PM_io_parser<PMDEC>::read_vertex() Halfedge_of[].

CVE-2020-28603

Multiple code execution vulnerabilities exist in the Nef polygon parsing functionality of CGAL. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which could lead to code execution. An attacker can provide malicious input to trigger any of these vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h PM_io_parser<PMDEC>::read_hedge() e->set_prev().

CVE-2020-28604

Multiple code execution vulnerabilities exist in the Nef polygon parsing functionality of CGAL. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which could lead to code execution. An attacker can provide malicious input to trigger any of these vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h PM_io_parser<PMDEC>::read_hedge() e->set_next().

CVE-2020-28605

Multiple code execution vulnerabilities exist in the Nef polygon parsing functionality of CGAL. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which could lead to code execution. An attacker can provide malicious input to trigger any of these vulnerabilities. An oob read exists in Nef_2/PM_io_parser.h PM_io_parser<PMDEC>::read_hedge() e->set_vertex().

CVE-2020-28606

Multiple code execution vulnerabilities exist in the Nef polygon parsing functionalityof CGAL. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which could lead to code execution. An attacker can provide malicious input to trigger any of these vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h PM_io_parser<PMDEC>::read_hedge() e->set_face().

CVE-2020-28607

Multiple code execution vulnerabilities exist in the Nef polygon parsing functionalityof CGAL. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which could lead to code execution. An attacker can provide malicious input to trigger any of these vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cgal' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libcgal-demo", ver:"4.13-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcgal-dev", ver:"4.13-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcgal-ipelets", ver:"4.13-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcgal-qt5-13", ver:"4.13-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcgal-qt5-dev", ver:"4.13-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcgal13", ver:"4.13-1+deb10u1", rls:"DEB10"))) {
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
