# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.162.1");
  script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1852", "CVE-2005-1916", "CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:01:37 +0000 (Fri, 26 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU5\.04");

  script_xref(name:"Advisory-ID", value:"USN-162-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-162-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ekg' package(s) announced via the USN-162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcin Owsiany and Wojtek Kaniewski discovered that some contributed
scripts (contrib/ekgh, contrib/ekgnv.sh, and contrib/getekg.sh) in the
ekg package created temporary files in an insecure way, which allowed
exploitation of a race condition to create or overwrite files with the
privileges of the user invoking the script. (CAN-2005-1850)

Marcin Owsiany and Wojtek Kaniewski discovered a shell command
injection vulnerability in a contributed utility
(contrib/scripts/ekgbot-pre1.py). By sending specially crafted content
to the bot, an attacker could exploit this to execute arbitrary code
with the privileges of the user running ekgbot. (CAN-2005-1851)

Marcin Slusarz discovered an integer overflow in the Gadu library. By
sending a specially crafted incoming message, a remote attacker could
execute arbitrary code with the privileges of the application using
libgadu. (CAN-2005-1852)

Eric Romang discovered that another contributed script
(contrib/scripts/linki.py) created temporary files in an insecure way,
which allowed exploitation of a race condition to create or overwrite
files with the privileges of the user invoking the script.
(CAN-2005-1916)

Grzegorz Jaskiewicz discovered several integer overflows in the Gadu
library. A remote attacker could exploit this to crash the Gadu client
application or even execute arbitrary code with the privileges of the
user by sending specially crafted messages. (CAN-2005-2369)

Szymon Zygmunt and Michal Bartoszkiewicz discovered a memory alignment
error in the Gadu library. By sending specially crafted messages, a
remote attacker could crash the application using the library.
(CAN-2005-2370)

Marcin Slusarz discovered that the Gadu library did not properly
handle endianness conversion in some cases. This caused invalid
behavior on big endian architectures. The only affected supported
architecture is powerpc. (CAN-2005-2448)");

  script_tag(name:"affected", value:"'ekg' package(s) on Ubuntu 5.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ekg", ver:"1.5-4ubuntu1.2", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-dev", ver:"1.5-4ubuntu1.2", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3", ver:"1.5-4ubuntu1.2", rls:"UBUNTU5.04"))) {
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
