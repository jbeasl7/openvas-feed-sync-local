# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0533");
  script_cve_id("CVE-2021-42376", "CVE-2021-42377", "CVE-2021-42378", "CVE-2021-42379", "CVE-2021-42380", "CVE-2021-42381", "CVE-2021-42382", "CVE-2021-42383", "CVE-2021-42384", "CVE-2021-42385", "CVE-2021-42386");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-17 19:41:56 +0000 (Wed, 17 Nov 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0533)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0533");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0533.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29697");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/6T2TURBYYJGBMQTTN2DSOAIQGP7WCPGV/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the MGASA-2021-0533 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference in Busybox's hush applet leads to denial of
service when processing a crafted shell command, due to missing validation
after a \x03 delimiter character. This may be used for DoS under very rare
conditions of filtered command input. (CVE-2021-42376)

An attacker-controlled pointer free in Busybox's hush applet leads to
denial of service and possible code execution when processing a crafted
shell command, due to the shell mishandling the &&& string. This may be
used for remote code execution under rare conditions of filtered command
input. (CVE-2021-42377)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
getvar_i function. (CVE-2021-42378)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
next_input_file function. (CVE-2021-42379)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
clrvar function. (CVE-2021-42380)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
hash_init function. (CVE-2021-42381)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
getvar_s function. (CVE-2021-42382)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
evaluate function. (CVE-2021-42383)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
handle_special function. (CVE-2021-42384)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
evaluate function. (CVE-2021-42385)

A use-after-free in Busybox's awk applet leads to denial of service and
possibly code execution when processing a crafted awk pattern in the
nvalloc function. (CVE-2021-42386)");

  script_tag(name:"affected", value:"'busybox' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.34.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.34.1~1.mga8", rls:"MAGEIA8"))) {
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
