# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0186");
  script_cve_id("CVE-2015-0278");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0186)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0186");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0186.html");
  script_xref(name:"URL", value:"http://blog.nodejs.org/2014/12/17/node-v0-10-34-stable/");
  script_xref(name:"URL", value:"http://blog.nodejs.org/2014/12/23/node-v0-10-35-stable/");
  script_xref(name:"URL", value:"http://blog.nodejs.org/2015/01/26/node-v0-10-36-stable/");
  script_xref(name:"URL", value:"http://blog.nodejs.org/2015/03/14/node-v0-10-37-stable/");
  script_xref(name:"URL", value:"http://blog.nodejs.org/2015/03/23/node-v0-10-38-maintenance/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15405");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150526.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2015-0186 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nodejs package fixes security vulnerability:

It was found that libuv does not call setgoups before calling setuid/setgid.
This may potentially allow an attacker to gain elevated privileges
(CVE-2015-0278).

The libuv library is bundled with nodejs, and a fixed version of libuv is
included with nodejs as of version 0.10.37. The nodejs package has been
updated to version 0.10.38 to fix this issue, as well as several other bugs.");

  script_tag(name:"affected", value:"'nodejs' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~0.10.38~1.mga4", rls:"MAGEIA4"))) {
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
