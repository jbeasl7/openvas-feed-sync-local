# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886487");
  script_cve_id("CVE-2024-2002");
  script_tag(name:"creation_date", value:"2024-05-27 10:41:43 +0000 (Mon, 27 May 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 13:15:07 +0000 (Mon, 18 Mar 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-60627905b6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-60627905b6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-60627905b6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267720");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272716");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libdwarf' package(s) announced via the FEDORA-2024-60627905b6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to latest upstream release.");

  script_tag(name:"affected", value:"'libdwarf' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"libdwarf", rpm:"libdwarf~0.9.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarf-debuginfo", rpm:"libdwarf-debuginfo~0.9.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarf-debugsource", rpm:"libdwarf-debugsource~0.9.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarf-devel", rpm:"libdwarf-devel~0.9.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarf-static", rpm:"libdwarf-static~0.9.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarf-tools", rpm:"libdwarf-tools~0.9.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdwarf-tools-debuginfo", rpm:"libdwarf-tools-debuginfo~0.9.2~1.fc40", rls:"FC40"))) {
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
