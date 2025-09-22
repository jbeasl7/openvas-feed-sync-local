# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53590");
  script_cve_id("CVE-2003-0143");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-259)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-259");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-259");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-259");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qpopper' package(s) announced via the DSA-259 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Heinz posted to the Bugtraq mailing list an exploit for qpopper based on a bug in the included vsnprintf implementation. The sample exploit requires a valid user account and password, and overflows a string in the pop_msg() function to give the user 'mail' group privileges and a shell on the system. Since the Qvsnprintf function is used elsewhere in qpopper, additional exploits may be possible.

The qpopper package in Debian 2.2 (potato) does not include the vulnerable snprintf implementation. For Debian 3.0 (woody) an updated package is available in version 4.0.4-2.woody.3. Users running an unreleased version of Debian should upgrade to 4.0.4-9 or newer. We recommend you upgrade your qpopper package immediately.");

  script_tag(name:"affected", value:"'qpopper' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"qpopper", ver:"4.0.4-2.woody.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qpopper-drac", ver:"4.0.4-2.woody.3", rls:"DEB3.0"))) {
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
