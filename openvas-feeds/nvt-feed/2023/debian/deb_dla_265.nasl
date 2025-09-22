# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.265");
  script_cve_id("CVE-2015-3206");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 20:44:03 +0000 (Fri, 08 Sep 2017)");

  script_name("Debian: Security Advisory (DLA-265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-265-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-265-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pykerberos' package(s) announced via the DLA-265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Martin Prpic has reported the possibility of a man-in-the-middle attack in the pykerberos code to the Red Hat Bugzilla (Fedora bug tracker). The original issue has earlier been reported upstream. We are quoting the upstream bug reported partially below:

The python-kerberos checkPassword() method has been badly insecure in previous releases. It used to do (and still does by default) a kinit (AS-REQ) to ask a KDC for a TGT for the given user principal, and interprets the success or failure of that as indicating whether the password is correct. It does not, however, verify that it actually spoke to a trusted KDC: an attacker may simply reply instead with an AS-REP which matches the password he just gave you.

Imagine you were verifying a password using LDAP authentication rather than Kerberos: you would, of course, use TLS in conjunction with LDAP to make sure you were talking to a real, trusted LDAP server. The same requirement applies here. kinit is not a password-verification service.

The usual way of doing this is to take the TGT you've obtained with the user's password, and then obtain a ticket for a principal for which the verifier has keys (e.g. a web server processing a username/password form login might get a ticket for its own HTTP/host@REALM principal), which it can then verify. Note that this requires that the verifier has its own Kerberos identity, which is mandated by the symmetric nature of Kerberos (whereas in the LDAP case, the use of public-key cryptography allows anonymous verification).

With this version of the pykerberos package a new option is introduced for the checkPassword() method. Setting verify to True when using checkPassword() will perform a KDC verification. For this to work, you need to provide a krb5.keytab file containing service principal keys for the service you intend to use.

As the default krb5.keytab file in /etc is normally not accessible by non-root users/processes, you have to make sure a custom krb5.keytab file containing the correct principal keys is provided to your application using the KRB5_KTNAME environment variable.

Note: In Debian squeeze(-lts), KDC verification support is disabled by default in order not to break existing setups.");

  script_tag(name:"affected", value:"'pykerberos' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"python-kerberos", ver:"1.1+svn4895-1+deb6u1", rls:"DEB6"))) {
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
