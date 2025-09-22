# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0529");
  script_cve_id("CVE-2013-6435", "CVE-2014-8118");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0529)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0529");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0529.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14766");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-1976.html");
  script_xref(name:"URL", value:"https://securityblog.redhat.com/2014/12/10/analysis-of-the-cve-2013-6435-flaw-in-rpm/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpm' package(s) announced via the MGASA-2014-0529 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that RPM wrote file contents to the target installation
directory under a temporary name, and verified its cryptographic signature
only after the temporary file has been written completely. Under certain
conditions, the system interprets the unverified temporary file contents
and extracts commands from it. This could allow an attacker to modify
signed RPM files in such a way that they would execute code chosen by the
attacker during package installation (CVE-2013-6435).

It was found that RPM could encounter an integer overflow, leading to a
stack-based buffer overflow, while parsing a crafted CPIO header in the
payload section of an RPM file. This could allow an attacker to modify
signed RPM files in such a way that they would execute code chosen by the
attacker during package installation (CVE-2014-8118).");

  script_tag(name:"affected", value:"'rpm' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64rpm-devel", rpm:"lib64rpm-devel~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpm3", rpm:"lib64rpm3~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpmbuild3", rpm:"lib64rpmbuild3~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rpmsign3", rpm:"lib64rpmsign3~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpm-devel", rpm:"librpm-devel~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpm3", rpm:"librpm3~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpmbuild3", rpm:"librpmbuild3~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librpmsign3", rpm:"librpmsign3~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rpm", rpm:"python-rpm~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.11.1~9.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sign", rpm:"rpm-sign~4.11.1~9.mga4", rls:"MAGEIA4"))) {
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
