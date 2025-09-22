# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0157");
  script_cve_id("CVE-2014-9706", "CVE-2015-0838");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0157)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0157");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0157.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15558");
  script_xref(name:"URL", value:"https://git.samba.org/?p=jelmer/dulwich.git;a=blob;f=NEWS;h=d0616a0c");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3206");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-dulwich' package(s) announced via the MGASA-2015-0157 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-dulwich package fixes security vulnerabilities:

It was discovered that Dulwich allows writing to files under .git/ when
checking out working trees. This could lead to the execution of arbitrary
code with the privileges of the user running an application based on Dulwich
(CVE-2014-9706).

Ivan Fratric of the Google Security Team has found a buffer overflow in the
C implementation of the apply_delta() function, used when accessing Git
objects in pack files. An attacker could take advantage of this flaw to
cause the execution of arbitrary code with the privileges of the user
running a Git server or client based on Dulwich (CVE-2015-0838).

The python-dulwich package has been updated to version 0.10.0, fixing these
issues and other bugs.");

  script_tag(name:"affected", value:"'python-dulwich' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"python-dulwich", rpm:"python-dulwich~0.10.0~1.mga4", rls:"MAGEIA4"))) {
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
