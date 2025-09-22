# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0185");
  script_cve_id("CVE-2017-9468", "CVE-2017-9469");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-13 18:13:30 +0000 (Tue, 13 Jun 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0185)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0185");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0185.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21037");
  script_xref(name:"URL", value:"https://www.ubuntu.com/usn/usn-3317-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi' package(s) announced via the MGASA-2017-0185 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Irssi incorrectly handled certain DCC messages.
A malicious IRC server could use this issue to cause Irssi to crash,
resulting in a denial of service (CVE-2017-9468).

Joseph Bisch discovered that Irssi incorrectly handled receiving
incorrectly quoted DCC files. A remote attacker could possibly use this
issue to cause Irssi to crash, resulting in a denial of service
(CVE-2017-9469).");

  script_tag(name:"affected", value:"'irssi' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"irssi", rpm:"irssi~0.8.21~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"irssi-devel", rpm:"irssi-devel~0.8.21~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"irssi-perl", rpm:"irssi-perl~0.8.21~1.1.mga5", rls:"MAGEIA5"))) {
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
