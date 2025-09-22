# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0262");
  script_cve_id("CVE-2014-3484");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-28 21:14:50 +0000 (Fri, 28 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0262)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0262");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0262.html");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q2/495");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13499");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'musl' package(s) announced via the MGASA-2014-0262 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated musl package fixes security vulnerability:

A remote stack-based buffer overflow has been found in musl libc's dns
response parsing code. The overflow can be triggered in programs linked
against musl libc and making dns queries via one of the standard interfaces
(getaddrinfo, getnameinfo, gethostbyname, gethostbyaddr, etc.) if one of the
configured nameservers in resolv.conf is controlled by an attacker, or if an
attacker can inject forged udp packets with control over their contents.
Denial of service is also possible via a related failure in loop detection
(CVE-2014-3484).");

  script_tag(name:"affected", value:"'musl' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"musl", rpm:"musl~0.9.14~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musl-devel", rpm:"musl-devel~0.9.14~2.1.mga4", rls:"MAGEIA4"))) {
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
