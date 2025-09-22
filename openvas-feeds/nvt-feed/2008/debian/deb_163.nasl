# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53731");
  script_cve_id("CVE-2002-0738");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-163)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-163");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/DSA-163");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-163");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mhonarc' package(s) announced via the DSA-163 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jason Molenda and Hiromitsu Takagi found ways to exploit cross site scripting bugs in mhonarc, a mail to HTML converter. When processing maliciously crafted mails of type text/html mhonarc does not deactivate all scripting parts properly. This is fixed in upstream version 2.5.3.

If you are worried about security, it is recommended that you disable support of text/html messages in your mail archives. There is no guarantee that the mhtxthtml.pl library is robust enough to eliminate all possible exploits that can occur with HTML data.

To exclude HTML data, you can use the MIMEEXCS resource. For example:

<MIMEExcs> text/html text/x-html </MIMEExcs>

The type 'text/x-html' is probably not used any more, but is good to include it, just-in-case.

If you are concerned that this could block out the entire contents of some messages, then you could do the following instead:

<MIMEFilters> text/html, m2h_text_plain::filter, mhtxtplain.pl text/x-html, m2h_text_plain::filter, mhtxtplain.pl </MIMEFilters>

This treats the HTML as text/plain.

The above problems have been fixed in version 2.5.2-1.1 for the current stable distribution (woody), in version 2.4.4-1.1 for the old stable distribution (potato) and in version 2.5.11-1 for the unstable distribution (sid).

We recommend that you upgrade your mhonarc packages.");

  script_tag(name:"affected", value:"'mhonarc' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mhonarc", ver:"2.5.2-1.1", rls:"DEB3.0"))) {
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
