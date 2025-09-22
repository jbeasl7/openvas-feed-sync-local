# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.313.1");
  script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-313-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-313-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-313-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org, openoffice.org-amd64' package(s) announced via the USN-313-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was possible to embed Basic macros in documents in a way that
OpenOffice.org would not ask for confirmation about executing them. By
tricking a user into opening a malicious document, this could be
exploited to run arbitrary Basic code (including local file access and
modification) with the user's privileges. (CVE-2006-2198)

A flaw was discovered in the Java sandbox which allowed Java applets
to break out of the sandbox and execute code without restrictions. By
tricking a user into opening a malicious document, this could be
exploited to run arbitrary code with the user's privileges. This
update disables Java applets for OpenOffice.org, since it is not
generally possible to guarantee the sandbox restrictions.
(CVE-2006-2199)

A buffer overflow has been found in the XML parser. By tricking a user
into opening a specially crafted XML file with OpenOffice.org, this
could be exploited to execute arbitrary code with the user's
privileges. (CVE-2006-3117)");

  script_tag(name:"affected", value:"'openoffice.org, openoffice.org-amd64' package(s) on Ubuntu 5.04, Ubuntu 6.06.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-bin", ver:"1.1.3-8ubuntu2.4", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.0.2-2ubuntu12.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.0.2-2ubuntu12.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.0.2-2ubuntu12.1", rls:"UBUNTU6.06 LTS"))) {
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
