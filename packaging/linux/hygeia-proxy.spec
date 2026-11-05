# RPM spec for the node (NOT YET BUILT OR TESTED: no rpmbuild in the dev environment).
# Build from a tree that contains target/release/hygeia-proxy and web/out:
#   rpmbuild -bb --build-in-place --define "_topdir $PWD/rpmbuild" packaging/linux/hygeia-proxy.spec
Name:           hygeia-proxy
Version:        0.1.0
Release:        1%{?dist}
Summary:        Hygieia node: local filtering server and browser-extension endpoint
License:        Apache-2.0
URL:            https://github.com/bytehawks-org/hygieia
BuildArch:      x86_64
%{?systemd_requires}
BuildRequires:  systemd-rpm-macros
AutoReqProv:    no
Requires:       glibc

%description
Light local server for the Hygieia browser extension with a local admin UI. Optional local DNS
filtering (off by default) and connected mode to a central Hygieia server. Installing does not
change the system resolver.

%build

%install
install -Dm755 target/release/hygeia-proxy %{buildroot}%{_bindir}/hygeia-proxy
install -Dm644 packaging/linux/hygeia-proxy.service %{buildroot}%{_unitdir}/hygeia-proxy.service
install -Dm644 packaging/linux/hygeia-proxy.toml %{buildroot}%{_sysconfdir}/hygeia-proxy/hygeia-proxy.toml
install -d %{buildroot}%{_datadir}/hygeia
cp -r web/out %{buildroot}%{_datadir}/hygeia/web

%post
%systemd_post hygeia-proxy.service
echo "Start with: systemctl enable --now hygeia-proxy ; then: sudo hygeia-proxy token"

%preun
%systemd_preun hygeia-proxy.service

%postun
%systemd_postun_with_restart hygeia-proxy.service

%files
%{_bindir}/hygeia-proxy
%{_unitdir}/hygeia-proxy.service
%config(noreplace) %{_sysconfdir}/hygeia-proxy/hygeia-proxy.toml
%{_datadir}/hygeia/web
