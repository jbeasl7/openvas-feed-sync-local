# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842767");
  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118");
  script_tag(name:"creation_date", value:"2016-05-19 03:20:59 +0000 (Thu, 19 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-13 13:58:43 +0000 (Wed, 13 Apr 2016)");

  script_name("Ubuntu: Security Advisory (USN-2950-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2950-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2950-4");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1574403");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1576109");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-2950-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2950-1 fixed vulnerabilities in Samba. The backported fixes introduced
in Ubuntu 12.04 LTS caused interoperability issues. This update fixes
compatibility with certain NAS devices, and allows connecting to Samba 3.6
servers by relaxing the 'client ipc signing' parameter to 'auto'.

We apologize for the inconvenience.

Original advisory details:

 Jouni Knuutinen discovered that Samba contained multiple flaws in the
 DCE/RPC implementation. A remote attacker could use this issue to perform
 a denial of service, downgrade secure connections by performing a
 machine-in-the-middle attack, or possibly execute arbitrary code.
 (CVE-2015-5370)

 Stefan Metzmacher discovered that Samba contained multiple flaws in the
 NTLMSSP authentication implementation. A remote attacker could use this
 issue to downgrade connections to plain text by performing a
 machine-in-the-middle attack. (CVE-2016-2110)

 Alberto Solino discovered that a Samba domain controller would establish a
 secure connection to a server with a spoofed computer name. A remote
 attacker could use this issue to obtain sensitive information.
 (CVE-2016-2111)

 Stefan Metzmacher discovered that the Samba LDAP implementation did not
 enforce integrity protection. A remote attacker could use this issue to
 hijack LDAP connections by performing a machine-in-the-middle attack.
 (CVE-2016-2112)

 Stefan Metzmacher discovered that Samba did not validate TLS certificates.
 A remote attacker could use this issue to spoof a Samba server.
 (CVE-2016-2113)

 Stefan Metzmacher discovered that Samba did not enforce SMB signing even if
 configured to. A remote attacker could use this issue to perform a
 machine-in-the-middle attack. (CVE-2016-2114)

 Stefan Metzmacher discovered that Samba did not enable integrity protection
 for IPC traffic. A remote attacker could use this issue to perform a
 machine-in-the-middle attack. (CVE-2016-2115)

 Stefan Metzmacher discovered that Samba incorrectly handled the MS-SAMR and
 MS-LSAD protocols. A remote attacker could use this flaw with a
 machine-in-the-middle attack to impersonate users and obtain sensitive
 information from the Security Account Manager database. This flaw is
 known as Badlock. (CVE-2016-2118)

 Samba has been updated to 4.3.8 in Ubuntu 14.04 LTS and Ubuntu 15.10.
 Ubuntu 12.04 LTS has been updated to 3.6.25 with backported security fixes.

 In addition to security fixes, the updated packages contain bug fixes,
 new features, and possibly incompatible changes. Configuration changes may
 be required in certain environments.");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:3.6.25-0ubuntu0.12.04.4", rls:"UBUNTU12.04 LTS"))) {
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
