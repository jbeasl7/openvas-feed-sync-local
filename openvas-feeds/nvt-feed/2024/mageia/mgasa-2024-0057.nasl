# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0057");
  script_cve_id("CVE-2023-24626");
  script_tag(name:"creation_date", value:"2024-03-14 04:12:02 +0000 (Thu, 14 Mar 2024)");
  script_version("2024-03-14T05:06:59+0000");
  script_tag(name:"last_modification", value:"2024-03-14 05:06:59 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 13:23:23 +0000 (Wed, 19 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0057");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0057.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32074");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6198-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'screen' package(s) announced via the MGASA-2024-0057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated package fixes a security vulnerability:
socket.c in GNU Screen through 4.9.0, when installed setuid or setgid
(the default on platforms such as Arch Linux and FreeBSD), allows local
users to send a privileged SIGHUP signal to any PID, causing a denial of
service or disruption of the target process. (CVE-2023-24626)");

  script_tag(name:"affected", value:"'screen' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"screen", rpm:"screen~4.9.0~4.1.mga9", rls:"MAGEIA9"))) {
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
