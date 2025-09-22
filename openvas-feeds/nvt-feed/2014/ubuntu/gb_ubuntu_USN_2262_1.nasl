# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841873");
  script_cve_id("CVE-2014-3144", "CVE-2014-3145");
  script_tag(name:"creation_date", value:"2014-07-01 16:41:20 +0000 (Tue, 01 Jul 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2262-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2262-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2262-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-quantal' package(s) announced via the USN-2262-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A bounds check error was discovered in the socket filter subsystem of the
Linux kernel. A local user could exploit this flaw to cause a denial of
service (system crash) via crafted BPF instructions. (CVE-2014-3144)

A remainder calculation error was discovered in the socket filter subsystem
of the Linux kernel. A local user could exploit this flaw to cause a denial
of service (system crash) via crafted BPF instructions. (CVE-2014-3145)");

  script_tag(name:"affected", value:"'linux-lts-quantal' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-52-generic", ver:"3.5.0-52.78~precise1", rls:"UBUNTU12.04 LTS"))) {
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
