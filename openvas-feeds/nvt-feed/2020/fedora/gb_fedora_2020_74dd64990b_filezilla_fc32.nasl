# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.878035");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2020-07-04 03:20:59 +0000 (Sat, 04 Jul 2020)");
  script_name("Fedora: Security Advisory for filezilla (FEDORA-2020-74dd64990b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"FEDORA", value:"2020-74dd64990b");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IRKUHQP6O6TGN64SI7PYCKHJT24Y2EY2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'filezilla'
  package(s) announced via the FEDORA-2020-74dd64990b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FileZilla is a FTP, FTPS and SFTP client for Linux with a lot of features.

  - Supports FTP, FTP over SSL/TLS (FTPS) and SSH File Transfer Protocol (SFTP)

  - Cross-platform

  - Available in many languages

  - Supports resume and transfer of large files greater than 4GB

  - Easy to use Site Manager and transfer queue

  - Drag & drop support

  - Speed limits

  - Filename filters

  - Network configuration wizard");

  script_tag(name:"affected", value:"'filezilla' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"filezilla", rpm:"filezilla~3.48.1~1.fc32", rls:"FC32"))) {
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
