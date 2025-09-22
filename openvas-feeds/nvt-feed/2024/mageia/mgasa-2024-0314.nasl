# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0314");
  script_cve_id("CVE-2024-36472");
  script_tag(name:"creation_date", value:"2024-09-27 04:11:17 +0000 (Fri, 27 Sep 2024)");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0314)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0314");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0314.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33434");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036098.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6963-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-shell' package(s) announced via the MGASA-2024-0314 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In GNOME Shell through 45.7, a portal helper can be launched
automatically (without user confirmation) based on network responses
provided by an adversary (e.g., an adversary who controls the local
Wi-Fi network), and subsequently loads untrusted JavaScript code, which
may lead to resource consumption or other impacts depending on the
JavaScript code's behavior. (CVE-2024-36472)");

  script_tag(name:"affected", value:"'gnome-shell' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~44.2~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-api_doc", rpm:"gnome-shell-api_doc~44.2~1.2.mga9", rls:"MAGEIA9"))) {
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
