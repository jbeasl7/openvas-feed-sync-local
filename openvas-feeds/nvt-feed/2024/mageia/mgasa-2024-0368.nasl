# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0368");
  script_cve_id("CVE-2024-50103", "CVE-2024-50108", "CVE-2024-50110", "CVE-2024-50111", "CVE-2024-50112", "CVE-2024-50115", "CVE-2024-50116", "CVE-2024-50117", "CVE-2024-50120", "CVE-2024-50121", "CVE-2024-50124", "CVE-2024-50125", "CVE-2024-50126", "CVE-2024-50127", "CVE-2024-50128", "CVE-2024-50130", "CVE-2024-50131", "CVE-2024-50133", "CVE-2024-50134", "CVE-2024-50135", "CVE-2024-50136", "CVE-2024-50139", "CVE-2024-50140", "CVE-2024-50141", "CVE-2024-50142", "CVE-2024-50143", "CVE-2024-50145", "CVE-2024-50147", "CVE-2024-50148", "CVE-2024-50150", "CVE-2024-50151", "CVE-2024-50152", "CVE-2024-50153", "CVE-2024-50154", "CVE-2024-50155", "CVE-2024-50156", "CVE-2024-50158", "CVE-2024-50159", "CVE-2024-50160", "CVE-2024-50162", "CVE-2024-50163", "CVE-2024-50164", "CVE-2024-50166", "CVE-2024-50167", "CVE-2024-50168", "CVE-2024-50169", "CVE-2024-50170", "CVE-2024-50171", "CVE-2024-50172", "CVE-2024-50205", "CVE-2024-50208", "CVE-2024-50209", "CVE-2024-50210", "CVE-2024-50211", "CVE-2024-50215", "CVE-2024-50216", "CVE-2024-50218", "CVE-2024-50219", "CVE-2024-50222", "CVE-2024-50223", "CVE-2024-50224", "CVE-2024-50226", "CVE-2024-50228", "CVE-2024-50229", "CVE-2024-50230", "CVE-2024-50231", "CVE-2024-50232", "CVE-2024-50233", "CVE-2024-50234", "CVE-2024-50235", "CVE-2024-50236", "CVE-2024-50237", "CVE-2024-50239", "CVE-2024-50240", "CVE-2024-50242", "CVE-2024-50243", "CVE-2024-50244", "CVE-2024-50245", "CVE-2024-50246", "CVE-2024-50247", "CVE-2024-50248", "CVE-2024-50249", "CVE-2024-50250", "CVE-2024-50251", "CVE-2024-50252", "CVE-2024-50255", "CVE-2024-50256", "CVE-2024-50257", "CVE-2024-50258", "CVE-2024-50259", "CVE-2024-50261", "CVE-2024-50262");
  script_tag(name:"creation_date", value:"2024-11-25 08:48:52 +0000 (Mon, 25 Nov 2024)");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-13 21:10:44 +0000 (Wed, 13 Nov 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0368)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0368");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0368.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33776");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.59");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.60");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.61");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2024-0368 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vanilla upstream kernel version 6.6.61 fixes bugs and vulnerabilities.
For information about the vulnerabilities see the links.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~6.6.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel", rpm:"kernel-linus-devel~6.6.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~6.6.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~6.6.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~6.6.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source", rpm:"kernel-linus-source~6.6.61~1.mga9", rls:"MAGEIA9"))) {
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
