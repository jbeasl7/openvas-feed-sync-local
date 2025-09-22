# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0227");
  script_cve_id("CVE-2022-31030");
  script_tag(name:"creation_date", value:"2022-06-14 04:45:21 +0000 (Tue, 14 Jun 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 01:26:02 +0000 (Thu, 16 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0227");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0227.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30525");
  script_xref(name:"URL", value:"https://github.com/containerd/containerd/security/advisories/GHSA-5ffw-gxpp-mxpf");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-containerd' package(s) announced via the MGASA-2022-0227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A bug was found in the containerd's CRI implementation where programs
inside a container can cause the containerd daemon to consume memory
without bound during invocation of the 'ExecSync' API. (CVE-2022-31030)");

  script_tag(name:"affected", value:"'docker-containerd' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-containerd", rpm:"docker-containerd~1.5.13~1.mga8", rls:"MAGEIA8"))) {
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
