# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0304");
  script_cve_id("CVE-2020-12695");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 00:24:58 +0000 (Thu, 18 Jun 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0304)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0304");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0304.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26918");
  script_xref(name:"URL", value:"https://mail.gnome.org/archives/gupnp-list/2020-June/msg00000.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gssdp, gupnp' package(s) announced via the MGASA-2020-0304 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Open Connectivity Foundation UPnP specification before 2020-04-17 does
not forbid the acceptance of a subscription request with a delivery URL on
a different network segment than the fully qualified event-subscription
URL, aka the CallStranger issue. (CVE-2020-12695).");

  script_tag(name:"affected", value:"'gssdp, gupnp' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"gssdp", rpm:"gssdp~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gupnp", rpm:"gupnp~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gssdp-devel", rpm:"lib64gssdp-devel~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gssdp-gir1.2", rpm:"lib64gssdp-gir1.2~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gssdp1.2_0", rpm:"lib64gssdp1.2_0~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gupnp-devel", rpm:"lib64gupnp-devel~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gupnp-gir1.2", rpm:"lib64gupnp-gir1.2~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gupnp1.2_0", rpm:"lib64gupnp1.2_0~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgssdp-devel", rpm:"libgssdp-devel~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgssdp-gir1.2", rpm:"libgssdp-gir1.2~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgssdp1.2_0", rpm:"libgssdp1.2_0~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgupnp-devel", rpm:"libgupnp-devel~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgupnp-gir1.2", rpm:"libgupnp-gir1.2~1.2.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgupnp1.2_0", rpm:"libgupnp1.2_0~1.2.3~1.mga7", rls:"MAGEIA7"))) {
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
