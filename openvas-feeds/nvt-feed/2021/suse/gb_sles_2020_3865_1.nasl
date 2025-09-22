# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3865.1");
  script_cve_id("CVE-2019-18348", "CVE-2019-20916", "CVE-2020-27619", "CVE-2020-8492");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 15:15:56 +0000 (Mon, 02 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3865-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3865-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203865-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179630");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-December/008081.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python36' package(s) announced via the SUSE-SU-2020:3865-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python36 fixes the following issues:

- CVE-2019-18348: Fixed a CRLF injection via the host part of the url passed to urlopen() (bsc#1155094)
- CVE-2019-20916: Fixed a directory traversal in _download_http_url() (bsc#1176262).
- CVE-2020-27619: Fixed an issue where the CJK codec tests call eval() on content retrieved via HTTP (bsc#1178009).
- CVE-2020-8492: Fixed a regular expression in urrlib that was prone to denial of service via HTTP (bsc#1162367).
- Working-around missing python-packaging dependency in python-Sphinx is not necessary anymore (bsc#1174571).
- Build of python3 documentation is not independent on the version of Sphinx(bsc#1179630).");

  script_tag(name:"affected", value:"'python36' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0", rpm:"libpython3_6m1_0~3.6.12~4.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python36", rpm:"python36~3.6.12~4.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python36-base", rpm:"python36-base~3.6.12~4.25.1", rls:"SLES12.0SP5"))) {
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
