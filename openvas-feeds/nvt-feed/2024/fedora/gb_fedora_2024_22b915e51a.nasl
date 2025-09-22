# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885731");
  script_cve_id("CVE-2023-45142");
  script_tag(name:"creation_date", value:"2024-02-20 02:03:55 +0000 (Tue, 20 Feb 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 18:27:50 +0000 (Wed, 18 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-22b915e51a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-22b915e51a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-22b915e51a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246587");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253698");
  script_xref(name:"URL", value:"https://github.com/caddyserver/caddy/releases/tag/v2.7.6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'caddy' package(s) announced via the FEDORA-2024-22b915e51a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to the latest upstream version, which includes a fix for CVE-2023-45142.

[link moved to references]");

  script_tag(name:"affected", value:"'caddy' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"caddy", rpm:"caddy~2.7.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-debuginfo", rpm:"caddy-debuginfo~2.7.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-debugsource", rpm:"caddy-debugsource~2.7.6~1.fc39", rls:"FC39"))) {
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
