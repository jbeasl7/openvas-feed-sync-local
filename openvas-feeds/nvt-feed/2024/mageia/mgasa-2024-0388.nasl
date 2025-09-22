# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0388");
  script_cve_id("CVE-2024-23334", "CVE-2024-52304");
  script_tag(name:"creation_date", value:"2024-12-05 04:13:16 +0000 (Thu, 05 Dec 2024)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 17:36:18 +0000 (Fri, 15 Aug 2025)");

  script_name("Mageia: Security Advisory (MGASA-2024-0388)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0388");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0388.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33544");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019855.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6991-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-aiohttp' package(s) announced via the MGASA-2024-0388 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When using aiohttp as a web server and configuring static routes, it is
necessary to specify the root path for static files. Additionally, the
option 'follow_symlinks' can be used to determine whether to follow
symbolic links outside the static root directory. When 'follow_symlinks'
is set to True, there is no validation to check if reading a file is
within the root directory. This can lead to directory traversal
vulnerabilities, resulting in unauthorized access to arbitrary files on
the system, even when symlinks are not present. Disabling
follow_symlinks and using a reverse proxy are encouraged mitigations.
CVE-2024-23334
The Python parser parses newlines in chunk extensions incorrectly which
can lead to request smuggling vulnerabilities under certain conditions.
If a pure Python version of aiohttp is installed (i.e. without the usual
C extensions) or `AIOHTTP_NO_EXTENSIONS` is enabled, then an attacker
may be able to execute a request smuggling attack to bypass certain
firewalls or proxy protections. CVE-2024-52304");

  script_tag(name:"affected", value:"'python-aiohttp' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp", rpm:"python-aiohttp~3.8.3~3.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp+speedups", rpm:"python3-aiohttp+speedups~3.8.3~3.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp", rpm:"python3-aiohttp~3.8.3~3.2.mga9", rls:"MAGEIA9"))) {
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
