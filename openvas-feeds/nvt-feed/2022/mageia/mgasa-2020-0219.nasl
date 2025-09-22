# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0219");
  script_cve_id("CVE-2019-17455");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-16 19:39:48 +0000 (Wed, 16 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0219)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0219");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0219.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26609");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2207");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libntlm' package(s) announced via the MGASA-2020-0219 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libntlm packages fix security vulnerability:

It was discovered that libntlm through 1.5 relies on a fixed buffer size
for tSmbNtlmAuthRequest, tSmbNtlmAuthChallenge, and tSmbNtlmAuthResponse
read and write operations, as demonstrated by a stack-based buffer
over-read in buildSmbNtlmAuthRequest in smbutil.c for a crafted NTLM
request (CVE-2019-17455).");

  script_tag(name:"affected", value:"'libntlm' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ntlm-devel", rpm:"lib64ntlm-devel~1.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ntlm0", rpm:"lib64ntlm0~1.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntlm", rpm:"libntlm~1.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntlm-devel", rpm:"libntlm-devel~1.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntlm0", rpm:"libntlm0~1.6~1.mga7", rls:"MAGEIA7"))) {
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
