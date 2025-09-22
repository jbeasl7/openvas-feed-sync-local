# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0359");
  script_cve_id("CVE-2015-20107", "CVE-2020-10735", "CVE-2021-28861");
  script_tag(name:"creation_date", value:"2022-10-10 04:44:17 +0000 (Mon, 10 Oct 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:33 +0000 (Wed, 09 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0359)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0359");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0359.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30848");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30929");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2VCU6EVQDIXNCEDJUCTFIER2WVNNDTYZ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OKYE2DOI2X7WZXAWTQJZAXYIWM37HDCY/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LSVFIZF6ZYMLK2HRCPTYDPZM3P6NDQKU/");
  script_xref(name:"URL", value:"https://pythoninsider.blogspot.com/2022/09/python-releases-3107-3914-3814-and-3714.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5629-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/09/21/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3, python-pip' package(s) announced via the MGASA-2022-0359 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Converting between int and str in bases other than 2 (binary), 4, 8
(octal), 16 (hexadecimal), or 32 such as base 10 (decimal) now raises a
ValueError if the number of digits in string form is above a limit to
avoid potential denial of service attacks due to the algorithmic
complexity. (CVE-2020-10735)
mailcap module does not add escape characters into commands discovered in
the system mailcap file. This may allow attackers to inject shell commands
into applications that call mailcap.findmatch with untrusted input (if
they lack validation of user-provided filenames or arguments).
(CVE-2015-20107)
Open redirection vulnerability in lib/http/server.py due to no protection
against multiple (/) at the beginning of URI path which may leads to
information disclosure. (CVE-2021-28861)
Also fixes permissions and title for the documentation.");

  script_tag(name:"affected", value:"'python3, python-pip' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64python3-devel", rpm:"lib64python3-devel~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.8", rpm:"lib64python3.8~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.8-stdlib", rpm:"lib64python3.8-stdlib~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.8-testsuite", rpm:"lib64python3.8-testsuite~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3-devel", rpm:"libpython3-devel~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.8", rpm:"libpython3.8~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.8-stdlib", rpm:"libpython3.8-stdlib~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.8-testsuite", rpm:"libpython3.8-testsuite~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip", rpm:"python-pip~22.0.4~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip-wheel", rpm:"python-pip-wheel~22.0.4~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~22.0.4~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3", rpm:"tkinter3~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3-apps", rpm:"tkinter3-apps~3.8.14~1.1.mga8", rls:"MAGEIA8"))) {
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
